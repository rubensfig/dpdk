/*
 * tx_occupancy_probe.c
 *
 * Minimal DPDK app to characterize rte_eth_tx_queue_count() behavior
 * under Tx shaping, targeting Marvell cnxk (CN10K/CN106) NIX PMD.
 *
 * Usage example (default = rte_tm shaping, 4 worker lcores -> 4 tx queues):
 *   ./tx_occupancy_probe -l 1,2,3,4 -- -p 0 -n 1024 -b 125000000 -s 0 -c
 * 5000000 -o samples
 *
 * App args (after --):
 *   -p PORT_ID     port to use (default 0)
 *   -n NB_DESC     nb_tx_desc, Tx ring depth (default 256)
 *   -b RATE_BPS    shaped rate in bps/sec via rte_tm (default shaping path).
 *                  0 = no shaping. 1 Gbit/s.
 *   -m BURST       packets requested per tx_burst call (default 32, clamped
 *                  to MAX_PKT_BURST=128).
 *   -s SLEEP_NS    busy-loop pacing between bursts in nanoseconds (0 = max
 * offered load) 
 *   -c COUNT       number of samples to collect (per queue) before
 * dumping and exiting 
 *   -o OUTFILE     base name for raw binary sample files;
 * each worker writes "<OUTFILE>_q<N>.bin" (uint16_t samples, one per tx_burst
 * call)
 *
 * Multi-core: every non-main lcore passed via EAL "-l" becomes a TX worker.
 * Worker i owns tx queue i (i = 0..n_workers-1). nb_tx_q is sized to the
 * number of worker lcores. The EAL main lcore does not push traffic; it
 * just sets things up, serves telemetry, and waits for workers to finish.
 *
 * Post-process with the Python histogram script separately.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_telemetry.h>
#include <rte_tm.h>

#define MAX_PKT_BURST 4096
#define WORK_PKTS 512
#define DEFAULT_BURST 32
#define MBUF_POOL_SIZE 16384
#define MBUF_CACHE_SIZE 256
#define PKT_LEN 64
#define MAX_TX_QUEUES 64
#define USED_HIST_MAX 4096

/* ---- CLI-configurable params (with defaults) ---- */
static uint16_t port_id = 0;
static uint16_t nb_tx_q = 1; /* recomputed from worker lcore count */
static uint16_t nb_tx_desc = 256;
static uint16_t burst_size = DEFAULT_BURST;
static uint64_t shaped_rate_bps = 0;  /* rte_tm API, bytes/sec, 0 = disabled */
static uint64_t legacy_rate_kbps = 0; /* legacy API, kbit/s */
static int use_tm = 1;         /* default: use rte_tm hierarchical shaper */
static uint64_t pacing_ns = 0; /* 0 = no pacing, max offered load */
static uint64_t target_samples = 1000000;
static char outfile_base[256] = "samples";
static uint32_t work_packets = WORK_PKTS;

/* TM node ids - arbitrary but must be unique within the hierarchy */
#define SHAPER_PROFILE_1 1
#define NODE_1000 1000
#define NODE_900 900
#define NODE_800 800
#define NODE_700 700

static volatile int force_quit = 0;

#define SAMPLE_FILE_MAGIC 0x5458424D /* "TXBM" */
#define SAMPLE_FILE_VERSION 1

struct queue_stats {
  uint64_t samples;

  uint16_t last_used;
  uint16_t min_used;
  uint16_t max_used;
  uint16_t reserved0;

  uint64_t sum_used;

  uint64_t tx_pkts;
  uint64_t tx_bytes;

  /*
   * All packets discarded by the application.
   */
  uint64_t tx_drops;

  /*
   * 
   * Not submitted because descriptor occupancy gating
   * reduced the burst.
   */
  uint64_t occupancy_gated;

  /*
  * Submitted to rte_eth_tx_burst(), but not accepted.
  */
  uint64_t tx_not_accepted;

  /*
  * Total mbufs explicitly freed by this benchmark.
  */
  uint64_t app_discarded;

  uint64_t used_polls;

  /*
   * Cycle counters.
   */
  uint64_t cycles_count;
  uint64_t cycles_tx;
  uint64_t cycles_total;
};
static struct queue_stats qstats[MAX_TX_QUEUES];

#define PAB_LIMIT_MIN     4u          /* pkts; seed, refine empirically */
#define PAB_GROW_STEP     16u          /* pkts, additive growth on starve */
#define PAB_TICK_US       200         /* interval tick, microseconds */
struct pab_bql {
	uint64_t num_queued;      /* cumulative pkts accepted by tx_burst */
	uint64_t num_completed;   /* cumulative pkts confirmed done by NIC */
	uint32_t limit;           /* adaptive per-TC pkt budget */
	uint64_t last_tick_cycles;
};

struct sample_record {
  /*
   * Queue state.
   */
  uint32_t used;
  uint32_t space;

  /*
   * Packet counts.
   */
  uint16_t requested;
  uint16_t to_send;
  uint16_t sent;

  uint16_t occupancy_gated;
  uint16_t tx_not_accepted;
  uint16_t reserved0;

  /*
   * Cost of the individual operations.
   */
  uint64_t cycles_count;
  uint64_t cycles_tx;
  uint64_t cycles_total;
};

struct sample_file_header {
  uint32_t magic;
  uint16_t version;
  uint16_t queue_id;

  uint32_t record_size;
  uint32_t stats_size;

  uint64_t num_records;

  uint32_t nb_tx_desc;
  uint32_t burst_size;

  uint64_t timer_hz;
};

static void parse_args(int argc, char **argv) {
  int opt;
  while ((opt = getopt(argc, argv, "p:n:t:r:b:m:s:c:o:L")) != -1) {
    switch (opt) {
    case 'p':
      port_id = (uint16_t)atoi(optarg);
      break;
    case 'n':
      nb_tx_desc = (uint16_t)atoi(optarg);
      break;
    case 't': /* kept for compatibility; nb_tx_q is derived from -l lcores */
      fprintf(stderr,
              "-t ignored: tx queue count is now derived from the number "
              "of EAL worker lcores (pass them via -l before --).\n");
      break;
    case 'r':
      legacy_rate_kbps = (uint64_t)atoll(optarg);
      break;
    case 'b':
      shaped_rate_bps = (uint64_t)atoll(optarg);
      break;
    case 'm':
      burst_size = (uint16_t)atoi(optarg);
      if (burst_size == 0 || burst_size > MAX_PKT_BURST) {
        fprintf(stderr, "-m %s out of range, clamping to [1,%d]\n", optarg,
                MAX_PKT_BURST);
        if (burst_size == 0)
          burst_size = 1;
        if (burst_size > MAX_PKT_BURST)
          burst_size = MAX_PKT_BURST;
      }
      break;
    case 's':
      pacing_ns = (uint64_t)atoll(optarg);
      break;
    case 'c':
      target_samples = (uint64_t)atoll(optarg);
      break;
    case 'o':
      strncpy(outfile_base, optarg, sizeof(outfile_base) - 1);
      break;
    case 'x':
      work_packets = (uint64_t)atoll(optarg);
      break;
    default:
      fprintf(stderr, "Unknown app option, ignoring.\n");
    }
  }
}

/*
 * rte_tm-based shaping setup (default path for cnxk/NIX, and the
 * spec-correct way to do hierarchical shaping in general).
 *
 * Builds a small hierarchy: root -> 900 -> 800 -> 700 -> one leaf node
 * per Tx queue, with a committed-rate shaper profile attached at the root.
 *
 * rate_bps is in bytes/sec (rte_tm shaper rates are bytes/sec, NOT bits/sec
 * like the legacy rte_eth_set_queue_rate_limit() kbps argument - easy
 * footgun when comparing the two APIs side by side).
 */
static int tm_shaper_setup(uint16_t pid, uint64_t rate_bps) {
  struct rte_tm_error error;
  struct rte_tm_shaper_params sp;
  struct rte_tm_node_params np;
  int ret;

  memset(&sp, 0, sizeof(sp));
  sp.committed.rate = 0;
  sp.committed.size = 0;
  sp.peak.rate = rate_bps;
  sp.peak.size = 16 * 1024;
  sp.pkt_length_adjust = 0;

  ret = rte_tm_shaper_profile_add(pid, SHAPER_PROFILE_1, &sp, &error);
  if (ret) {
    fprintf(stderr, "shaper_profile_add failed: ret=%d type=%d msg=%s\n", ret,
            error.type, error.message ? error.message : "NULL");
    return ret;
  }

  memset(&np, 0, sizeof(np));
  np.shaper_profile_id = SHAPER_PROFILE_1;
  np.nonleaf.n_sp_priorities = 1;
  ret = rte_tm_node_add(pid, NODE_1000, RTE_TM_NODE_ID_NULL, 0, 1, 0, &np,
                        &error);
  if (ret)
    goto fail;

  memset(&np, 0, sizeof(np));
  np.shaper_profile_id = RTE_TM_SHAPER_PROFILE_ID_NONE;
  np.nonleaf.n_sp_priorities = 1;
  ret = rte_tm_node_add(pid, NODE_900, NODE_1000, 0, 1, 1, &np, &error);
  if (ret)
    goto fail;

  memset(&np, 0, sizeof(np));
  np.shaper_profile_id = RTE_TM_SHAPER_PROFILE_ID_NONE;
  np.nonleaf.n_sp_priorities = 1;
  ret = rte_tm_node_add(pid, NODE_800, NODE_900, 0, 1, 2, &np, &error);
  if (ret)
    goto fail;

  memset(&np, 0, sizeof(np));
  np.shaper_profile_id = RTE_TM_SHAPER_PROFILE_ID_NONE;
  np.nonleaf.n_sp_priorities = 1;
  ret = rte_tm_node_add(pid, NODE_700, NODE_800, 0, 1, 3, &np, &error);
  if (ret)
    goto fail;

  memset(&np, 0, sizeof(np));
  np.shaper_profile_id = RTE_TM_SHAPER_PROFILE_ID_NONE;
  np.leaf.cman = RTE_TM_CMAN_TAIL_DROP;
  for (int i = 0; i < nb_tx_q; i++) {
    ret = rte_tm_node_add(pid, i, NODE_700, 0, 1, 4, &np, &error);
    if (ret) {
      fprintf(stderr, "node_add(queue %d) failed: ret=%d type=%d msg=%s\n", i,
              ret, error.type, error.message ? error.message : "NULL");
      return ret;
    }
  }

  ret = rte_tm_hierarchy_commit(pid, 1, &error);
  if (ret) {
    fprintf(stderr, "hierarchy_commit failed: ret=%d type=%d msg=%s\n", ret,
            error.type, error.message ? error.message : "NULL");
    return ret;
  }
  printf("passed\n");
  return 0;

fail:
  fprintf(stderr, "tm_shaper_setup: ret=%d type=%d msg=%s\n", ret, error.type,
          error.message ? error.message : "NULL");
  return ret;
}

static int port_init(uint16_t pid, struct rte_mempool *mbuf_pool) {
  struct rte_eth_conf port_conf = {0};
  struct rte_eth_dev_info dev_info;
  struct rte_eth_txconf txconf;
  int ret;

  ret = rte_eth_dev_info_get(pid, &dev_info);
  if (ret != 0) {
    fprintf(stderr, "rte_eth_dev_info_get failed: %s\n", strerror(-ret));
    return ret;
  }

  /* 1 RX queue (unused but some PMDs require >=1), nb_tx_q TX queues,
   * one per TX worker lcore. */
  ret = rte_eth_dev_configure(pid, 1, nb_tx_q, &port_conf);
  if (ret != 0)
    return ret;

  ret = rte_eth_rx_queue_setup(pid, 0, 128, rte_eth_dev_socket_id(pid), NULL,
                               mbuf_pool);
  if (ret != 0)
    return ret;

  txconf = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  for (int i = 0; i < nb_tx_q; i++) {
    ret = rte_eth_tx_queue_setup(pid, i, nb_tx_desc, rte_eth_dev_socket_id(pid),
                                 &txconf);
    if (ret != 0) {
      fprintf(stderr, "tx_queue_setup(%d) failed: %d\n", i, ret);
      return ret;
    }
  }

  /* ---- Shaping setup: rte_tm is the default and must happen BEFORE
   * rte_eth_dev_start() on cnxk (hierarchy commit while stopped). ---- */
  if (use_tm && shaped_rate_bps > 0) {
    ret = tm_shaper_setup(pid, shaped_rate_bps);
    if (ret != 0) {
      fprintf(stderr,
              "rte_tm shaper setup failed (%d). Falling back to no shaping "
              "for this run. Check rte_tm capability negotiation "
              "(rte_tm_capabilities_get / rte_tm_level_capabilities_get) "
              "against what cnxk actually supports in your DPDK version.\n",
              ret);
      shaped_rate_bps = 0;
    }
  } else if (!use_tm && legacy_rate_kbps > 0) {
    for (int i = 0; i < nb_tx_q; i++) {
      ret = rte_eth_set_queue_rate_limit(pid, i, legacy_rate_kbps);
      if (ret != 0) {
        fprintf(stderr, "rte_eth_set_queue_rate_limit(queue %d) failed: %d\n",
                i, ret);
      }
    }
  }

  ret = rte_eth_dev_start(pid);
  if (ret != 0)
    return ret;

  struct rte_eth_link link;
  rte_eth_link_get(pid, &link);
  printf("link: up=%d speed=%u duplex=%s\n", link.link_status, link.link_speed,
         link.link_duplex ? "full" : "half");

  rte_eth_promiscuous_enable(pid);

  return 0;
}

static inline void fill_dummy_packet(struct rte_mbuf *m) {
  char *data = rte_pktmbuf_append(m, PKT_LEN);
  memset(data, 0xAA, PKT_LEN);
  m->data_len = PKT_LEN;
  m->pkt_len = PKT_LEN;
}

struct worker_ctx {
  uint16_t queue_id;
  struct rte_mempool *mbuf_pool;
  struct sample_record *samples;
};

static struct worker_ctx worker_ctx[MAX_TX_QUEUES];

static int tx_worker_main(void *arg) {
  struct worker_ctx *ctx = (struct worker_ctx *)arg;
  uint16_t queue_id = ctx->queue_id;
  uint64_t sample_idx = 0;
  uint64_t hz = rte_get_timer_hz();
  struct queue_stats *qs = &qstats[queue_id];
  uint64_t start_tsc = rte_get_timer_cycles();
  uint64_t last_tsc = start_tsc;
  uint64_t last_tx = 0;
  const uint32_t txq_used_floor = 126U;

  uint64_t used_hist[USED_HIST_MAX] = {0};

 struct pab_bql bql[N_TC];

  while (sample_idx < target_samples && !force_quit) {
    struct rte_mbuf *bufs[WORK_PKTS];

    if (rte_pktmbuf_alloc_bulk(ctx->mbuf_pool, bufs, work_packets) != 0)
      continue;

    for (uint16_t i = 0; i < work_packets; i++)
      fill_dummy_packet(bufs[i]);

    struct sample_record *s = &ctx->samples[sample_idx];
    memset(s, 0, sizeof(*s));

    s->requested = work_packets;

	s->used = UINT32_MAX; // no valid queue count observation

    uint64_t loop_t0 = rte_rdtsc();


    /*
     * ----------------------------------------------------------
     * TX fixed WORK_PKTS packets using burst_size chunks
     * ----------------------------------------------------------
     */
    uint32_t total_to_send = 0;
    uint32_t total_sent = 0;
    uint32_t total_not_accepted = 0;
	uint64_t total_gated = 0;

    uint64_t cycles_tx = 0;
    uint64_t cycles_count = 0;

    uint16_t offset = 0;

    while (offset < work_packets && !force_quit) {
        uint16_t remaining = (uint16_t)(work_packets - offset);
	uint16_t requested = RTE_MIN(burst_size, remaining);

#if COMP
	/*
	 * ----------------------------------------------------------
	 * Poll descriptor occupancy
	 * ----------------------------------------------------------
	 */
	uint64_t t2 = rte_rdtsc();
	int used = rte_eth_tx_queue_count(port_id, queue_id);
	uint64_t t3 = rte_rdtsc();
	cycles_count += t3 - t2;

	if (unlikely(used < 0)) {
	  s->used = UINT32_MAX;
	  break;
	} 
	
	uint32_t raw_used = (uint32_t) used;

	if (raw_used < USED_HIST_MAX)
    		used_hist[raw_used]++;

	  s->used = (uint32_t)used;
	  qs->last_used = (uint16_t)used;

	if (qs->used_polls == 0) {
            qs->min_used = (uint16_t)raw_used;
            qs->max_used = (uint16_t)raw_used;
        } else {
            if (raw_used < qs->min_used)
                qs->min_used = (uint16_t)raw_used;

            if (raw_used > qs->max_used)
                qs->max_used = (uint16_t)raw_used;
        }

	qs->sum_used += raw_used;
	qs->used_polls++;

	//  2. Normalize the platform-specific occupancy floor.
	uint32_t effective_used =
            (raw_used > txq_used_floor)
                ? raw_used - txq_used_floor
                : 0U;

	uint16_t free_space = (effective_used >= (uint32_t)nb_tx_desc)
		? 0U
		: (uint32_t) nb_tx_desc - effective_used;

        // uint16_t to_send = RTE_MIN(requested, free_space);
        uint16_t to_send = requested;

	uint16_t gated = requested - to_send;

	total_gated += gated;
#endif
#if BQL
	        uint64_t t2 = rte_rdtsc();

		if (now_cycles - bql.last_tick_cycles >= pab_tick_cycles) {
			int freed = rte_eth_tx_done_cleanup(port_id, queue_id, 0);

			if (freed > 0)
				bql.num_completed += (uint64_t)freed;

			int had_demand = (requested > 0);
			uint64_t inflight = bql.num_queued - bql.num_completed;

			if (inflight == 0 && had_demand) {
				bql.limit += PAB_GROW_STEP;	
				if (bql.limit > nb_tx_desc)
					bql.limit = nb_tx_desc;

			} else if (inflight >= bql.limit && had_demand) {
				bql.limit = (bql.limit > PAB_GROW_STEP)
					? bql.limit - PAB_GROW_STEP
					: PAB_LIMIT_MIN;

				if (bql.limit < PAB_LIMIT_MIN)
					bql.limit = PAB_LIMIT_MIN;
			}

			bql.last_tick_cycles = now_cycles;
		}

		uint64_t t3 = rte_rdtsc();
		cycles_count += t3 - t2;


		uint64_t inflight_now = bql.num_queued - bql.num_completed;
		uint32_t raw_used = (inflight_now > UINT32_MAX) ? UINT32_MAX : (uint32_t)inflight_now;

if (raw_used < USED_HIST_MAX)
used_hist[raw_used]++;

s->used = raw_used;
qs->last_used = (uint16_t)raw_used;

if (qs->used_polls == 0) {
qs->min_used = (uint16_t)raw_used;
qs->max_used = (uint16_t)raw_used;
} else {
if (raw_used < qs->min_used)
qs->min_used = (uint16_t)raw_used;

if (raw_used > qs->max_used)
qs->max_used = (uint16_t)raw_used;
}

qs->sum_used += raw_used;
qs->used_polls++;

/* bql_space: room left under the adaptive limit, capped to desc ring */
uint32_t bql_space = (bql.limit > inflight_now)
? (uint32_t)(bql.limit - inflight_now)
: 0U;

uint16_t free_space = (uint32_t)nb_tx_desc < bql_space
? (uint16_t)nb_tx_desc
: (uint16_t)bql_space;

uint16_t to_send = RTE_MIN(requested, free_space);

uint16_t gated = requested - to_send;

total_gated += gated;


#endif


        /*
         * Measure only rte_eth_tx_burst().
         */
        uint64_t t4 = rte_rdtsc();

        uint16_t sent =
            rte_eth_tx_burst(port_id,
                             queue_id,
                             &bufs[offset],
                             to_send);

        uint64_t t5 = rte_rdtsc();

        cycles_tx += t5 - t4;
        total_sent += sent;

        uint16_t tx_not_accepted = to_send - sent;
        total_not_accepted += tx_not_accepted;

        if (unlikely(tx_not_accepted)) {
            for (uint16_t i = sent; i < to_send; i++)
                rte_pktmbuf_free(bufs[offset + i]);
        }

        /*
         * Move to the next group of packets.
         *
         * We advance by to_send, not sent, because rejected packets
         * from this group have already been freed above.
         */
        offset += to_send;
    }
        /*
     * ----------------------------------------------------------
     * Store completed sample results.
     * ----------------------------------------------------------
     */
    s->to_send = total_to_send;
    s->sent = total_sent;
    s->tx_not_accepted = total_not_accepted;

    s->cycles_count = cycles_count;
    s->cycles_tx = cycles_tx;

    uint64_t loop_t1 = rte_rdtsc();

    s->cycles_total = loop_t1 - loop_t0;

    /*
     * ----------------------------------------------------------
     * Queue-level accounting
     * ----------------------------------------------------------
     */
    qs->tx_pkts += total_sent;
    qs->tx_bytes +=
        (uint64_t)total_sent * PKT_LEN;

    qs->tx_not_accepted += total_not_accepted;

    /*
     * Only TX-admitted-but-rejected packets were actually
     * discarded by this benchmark.
     *
     * Proactively gated packets were deferred and eventually
     * reconsidered, so they are NOT app_discarded.
     */
    qs->app_discarded += total_not_accepted;

    /*
     * This represents proactive gating decisions, not unique
     * dropped packets.
     */
    qs->occupancy_gated += total_gated;

    qs->cycles_count += s->cycles_count;
    qs->cycles_tx += s->cycles_tx;
    qs->cycles_total += s->cycles_total;

    sample_idx++;
    qs->samples = sample_idx;
  }

  printf("\n"
         "========== Queue %u benchmark ==========\n"
         "samples             : %" PRIu64 "\n"
         "tx_pkts             : %" PRIu64 "\n"
         "tx_bytes            : %" PRIu64 "\n"
         "app_discarded       : %" PRIu64 "\n"
         "\n"
	 "occupancy_polls         : %" PRIu64 "\n"
         "polls_per_sample        : %.2f\n"
         "\n"
         "occupancy_gated     : %" PRIu64 "\n"
         "tx_not_accepted     : %" PRIu64 "\n"
         "\n"
         "last_used           : %u\n"
         "min_used            : %u\n"
         "max_used            : %u\n"
         "avg_used            : %.2f\n"
         "\n"
         "cycles_count        : %" PRIu64 "\n"
         "cycles_tx           : %" PRIu64 "\n"
         "cycles_total        : %" PRIu64 "\n"
         "\n"
         "avg_cycles_count    : %.2f\n"
         "avg_cycles_tx       : %.2f\n"
         "avg_cycles_total    : %.2f\n"
         "=========================================\n",
         queue_id,

         qs->samples, qs->tx_pkts, qs->tx_bytes, qs->app_discarded,
	 qs->used_polls, qs->samples
           ? (double)qs->used_polls / (double)qs->samples
           : 0.0,
         qs->occupancy_gated, qs->tx_not_accepted,
         qs->last_used, qs->min_used, qs->max_used,
         qs->samples ? (double)qs->sum_used / (double)qs->used_polls : 0.0,
         qs->cycles_count, qs->cycles_tx, qs->cycles_total,
         qs->samples ? (double)qs->cycles_count / qs->used_polls : 0.0,
         qs->samples ? (double)qs->cycles_tx / qs->samples : 0.0,
         qs->samples ? (double)qs->cycles_total / qs->samples : 0.0);

  printf("\nTX queue-count histogram:\n");

	for (uint32_t i = 0; i < USED_HIST_MAX; i++) {
	    if (used_hist[i] != 0) {
		printf("  used=%3u : %" PRIu64 " (%.4f%%)\n",
		       i,
		       used_hist[i],
		       100.0 * (double)used_hist[i] /
			   (double)qs->used_polls);
	    }
	}

  char fname[300];

  snprintf(fname, sizeof(fname), "%s_q%u.bin", outfile_base, queue_id);

  FILE *f = fopen(fname, "wb");

  if (f == NULL) {
    fprintf(stderr, "[q%u] Could not open %s for writing\n", queue_id, fname);
  } else {
    struct sample_file_header hdr = {
        .magic = SAMPLE_FILE_MAGIC,
        .version = SAMPLE_FILE_VERSION,
        .queue_id = queue_id,

        .record_size = sizeof(struct sample_record),
        .stats_size = sizeof(struct queue_stats),

        .num_records = sample_idx,

        .nb_tx_desc = nb_tx_desc,
        .burst_size = burst_size,

        .timer_hz = rte_get_timer_hz(),
    };

    /*
     * File layout:
     *
     * +---------------------+
     * | sample_file_header  |
     * +---------------------+
     * | queue_stats         |
     * +---------------------+
     * | sample_record[0]    |
     * +---------------------+
     * | sample_record[1]    |
     * +---------------------+
     * | ...                 |
     * +---------------------+
     */

    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(qs, sizeof(*qs), 1, f);
    fwrite(ctx->samples, sizeof(struct sample_record), sample_idx, f);

    fclose(f);

    printf("[q%u] wrote %" PRIu64 " samples + queue stats to %s "
           "(record=%zu bytes, stats=%zu bytes)\n",
           queue_id, sample_idx, fname, sizeof(struct sample_record),
           sizeof(struct queue_stats));
  }

  return 0;
}

int main(int argc, char **argv) {
  int ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "EAL init failed\n");
  argc -= ret;
  argv += ret;

  parse_args(argc, argv);

  /* ---- Derive tx queue count from worker lcores ---- */
  unsigned worker_lcores[MAX_TX_QUEUES];
  unsigned n_workers = 0;
  unsigned lc;
  RTE_LCORE_FOREACH_WORKER(lc) {
    if (n_workers >= MAX_TX_QUEUES) {
      fprintf(stderr, "Too many worker lcores, capping at %d\n", MAX_TX_QUEUES);
      break;
    }
    worker_lcores[n_workers++] = lc;
  }

  if (n_workers == 0) {
    /* Only the main lcore was given (-l <one core>); use it as the
     * sole TX worker instead of refusing to run. */
    worker_lcores[0] = rte_lcore_id();
    n_workers = 1;
    printf("Only one lcore available; running single TX worker on the "
           "main lcore.\n");
  }

  nb_tx_q = (uint16_t)n_workers;

  struct rte_mempool *mbuf_pool =
      rte_pktmbuf_pool_create("MBUF_POOL", MBUF_POOL_SIZE, MBUF_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

  if (port_init(port_id, mbuf_pool) != 0)
    rte_exit(EXIT_FAILURE, "Port init failed\n");

  // register_telemetry();

  printf("Port %u up. workers=%u nb_tx_q=%u nb_tx_desc=%u burst=%u "
         "method=%s shaped_rate=%ld pacing_ns=%lu target_samples=%lu\n",
         port_id, n_workers, nb_tx_q, nb_tx_desc, burst_size,
         use_tm ? "rte_tm" : "legacy", (shaped_rate_bps ? shaped_rate_bps : 0),
         (unsigned long)pacing_ns, (unsigned long)target_samples);

  /* ---- Allocate per-queue sample buffers and launch workers ---- */
  for (unsigned i = 0; i < n_workers; i++) {
    uint16_t q = (uint16_t)i;

    struct sample_record *samples =
        rte_zmalloc("samples", target_samples * sizeof(struct sample_record),
                    RTE_CACHE_LINE_SIZE);

    if (samples == NULL)
      rte_exit(EXIT_FAILURE, "Cannot allocate sample buffer for queue %u\n", q);

    worker_ctx[i].queue_id = q;
    worker_ctx[i].mbuf_pool = mbuf_pool;
    worker_ctx[i].samples = samples;

    if (worker_lcores[i] == rte_lcore_id()) {
      /* Single-worker fallback case: run inline on main lcore. */
      tx_worker_main(&worker_ctx[i]);
    } else {
      ret = rte_eal_remote_launch(tx_worker_main, &worker_ctx[i],
                                  worker_lcores[i]);
      if (ret != 0)
        fprintf(stderr, "Failed to launch worker on lcore %u: %d\n",
                worker_lcores[i], ret);
    }
  }

  rte_eal_mp_wait_lcore();

  for (unsigned i = 0; i < n_workers; i++)
    rte_free(worker_ctx[i].samples);

  rte_eth_dev_stop(port_id);
  rte_eth_dev_close(port_id);
  rte_eal_cleanup();
  return 0;
}
