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
 *   -c COUNT       maximum raw sample records stored per queue. The timed
 *                  measurement continues even if this capacity is reached.
 *   -w WARMUP_MS   common warm-up duration in milliseconds (default 100).
 *   -d MEASURE_MS  common measurement duration in milliseconds (default 100).
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

#include <inttypes.h>
#include <stdbool.h>
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
#include <rte_pause.h>
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

#if defined(COMP) && defined(BQL)
#error "COMP and BQL cannot both be enabled"
#endif

/* ---- CLI-configurable params (with defaults) ---- */
static uint16_t port_id = 0;
static uint16_t nb_tx_q = 1; /* recomputed from worker lcore count */
static uint16_t nb_tx_desc = 256;
static uint16_t burst_size = DEFAULT_BURST;
static uint64_t shaped_rate_bps = 0;  /* rte_tm API, bytes/sec, 0 = disabled */
static uint64_t legacy_rate_kbps = 0; /* legacy API, kbit/s */
static int use_tm = 1;         /* default: use rte_tm hierarchical shaper */
static uint64_t pacing_ns = 0; /* 0 = no pacing, max offered load */
/*
 * In synchronized mode, -c is a raw-record capacity, not a stop condition.
 * Statistics continue for the entire common measurement window even if a
 * queue produces more than target_samples iterations; excess raw records are
 * not stored and a warning is printed.
 */
static uint64_t target_samples = 1000000;
static uint64_t warmup_ms = 100;
static uint64_t measure_ms = 100;
static char outfile_base[256] = "samples";
static uint32_t work_packets = WORK_PKTS;


// {
#ifdef COMP
#define COMP_RELAX_STREAK 1024u
#define COMP_NEAR_STEPS 2u
#define COMP_REDUCED_DIV 4u

struct comp_state {
  uint32_t high_wm;

  uint32_t last_used;
  uint32_t observed_step;

  uint32_t success_streak;

  bool have_last;
  bool wm_valid;
};

static inline uint32_t comp_gcd_u32(uint32_t a, uint32_t b) {
  while (b) {
    uint32_t t = a % b;
    a = b;
    b = t;
  }

  return a;
}

static inline void comp_observe(struct comp_state *c, uint32_t used) {
  if (c->have_last) {
    uint32_t delta =
        used > c->last_used ? used - c->last_used : c->last_used - used;

    if (delta) {
      if (c->observed_step == 0)
        c->observed_step = delta;
      else
        c->observed_step = comp_gcd_u32(c->observed_step, delta);
    }
  }

  c->last_used = used;
  c->have_last = true;
}

static inline bool comp_near_high(const struct comp_state *c, uint32_t used) {
  if (!c->wm_valid || !c->observed_step || used >= c->high_wm)
    return false;

  uint64_t distance = (uint64_t)c->high_wm - used;
  uint64_t margin = (uint64_t)c->observed_step * COMP_NEAR_STEPS;

  return distance <= margin;
}

/*
 * Queue-count units are opaque.
 *
 * We never calculate:
 *
 *     high_wm - used == number of packets available
 *
 * The signal is only used to classify queue pressure.
 */
static inline uint16_t comp_admit(const struct comp_state *c, uint32_t used,
                                  uint16_t requested) {
  /* Before congestion has ever been identified: fail open. */
  if (!c->wm_valid)
    return requested;

  /* Queue pressure at/above learned unsafe boundary. */
  if (used >= c->high_wm)
    return 0;

  /*
   * Close to the boundary: probe conservatively.
   * This remains in packet/burst space, independent of occupancy units.
   */
  if (comp_near_high(c, used)) {
    uint16_t reduced = requested / COMP_REDUCED_DIV;

    if (reduced == 0)
      reduced = 1;

    return reduced;
  }

  return requested;
}
static inline void comp_feedback(struct comp_state *c, uint32_t used,
                                 uint16_t attempted, uint16_t sent) {
  if (attempted == 0)
    return;

  if (sent < attempted) {
    /*
     * Do not arm COMP until the queue-count signal has shown
     * some variation. This avoids treating a constant baseline
     * value as a congestion threshold.
     */
    if (c->observed_step == 0)
      return;

    if (!c->wm_valid || used < c->high_wm)
      c->high_wm = used;

    c->wm_valid = true;
    c->success_streak = 0;
    return;
  }

  if (!c->wm_valid || !c->observed_step) {
    c->success_streak = 0;
    return;
  }

  if (comp_near_high(c, used)) {
    c->success_streak++;

    if (c->success_streak >= COMP_RELAX_STREAK) {
      if (UINT32_MAX - c->high_wm >= c->observed_step)
        c->high_wm += c->observed_step;

      c->success_streak = 0;
    }
  } else {
    c->success_streak = 0;
  }
}

#endif
// }

// {
#ifdef BQL

#define PAB_LIMIT_MIN 2u
#define PAB_GROW_STEP 64u

struct pab_bql {
  uint64_t num_queued;
  uint64_t num_completed;

  uint32_t limit;

  uint64_t last_tick_cycles;
  uint64_t tick_cycles;

  bool cleanup_error_reported;
};

#endif
// }

#define SYNC_LEAD_MS 10u

/*
 * Two worker-only barriers:
 *   1) all workers ready -> last worker publishes common warm-up window
 *   2) all workers finish warm-up -> last worker publishes measurement window
 *
 * GCC/Clang __atomic builtins are used so this also works for the single-lcore
 * fallback without requiring the main lcore to participate in a barrier.
 */
static uint32_t sync_n_workers;
static uint32_t sync_workers_ready;
static uint32_t sync_warmup_done;
static uint32_t sync_warmup_schedule_ready;
static uint32_t sync_measure_schedule_ready;
static uint64_t global_warmup_start_tsc;
static uint64_t global_warmup_end_tsc;
static uint64_t global_start_tsc;
static uint64_t global_end_tsc;

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

  uint64_t reject_events;
  uint64_t first_reject_sample;
  uint64_t last_reject_sample;

  /*
   * Cycle counters.
   */
  uint64_t cycles_count;
  uint64_t cycles_tx;
  uint64_t cycles_total;
};
static struct queue_stats qstats[MAX_TX_QUEUES];

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
  while ((opt = getopt(argc, argv, "p:n:t:r:b:m:s:c:o:w:d:x:L")) != -1) {
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
      outfile_base[sizeof(outfile_base) - 1] = '\0';
      break;
    case 'w':
      warmup_ms = (uint64_t)atoll(optarg);
      break;
    case 'd':
      measure_ms = (uint64_t)atoll(optarg);
      if (measure_ms == 0) {
        fprintf(stderr, "-d must be > 0 ms; using 1 ms\n");
        measure_ms = 1;
      }
      break;
    case 'x':
      work_packets = (uint64_t)atoll(optarg);
      break;
    default:
      fprintf(stderr, "Unknown app option, ignoring.\n");
    }
  }
}

static void
write_queue_json(uint16_t queue_id,
                 const struct queue_stats *qs,
                 uint64_t recorded_samples,
                 uint64_t offered_pkts,
                 uint64_t attempted_pkts,
                 double gating_pct,
                 double rejection_pct,
                 double tx_pkts_per_second,
                 const uint64_t used_hist[USED_HIST_MAX],
                 const uint64_t watermark_hist[USED_HIST_MAX])
{
    char fname[300];
    snprintf(fname, sizeof(fname), "%s_q%u.json",
             outfile_base, queue_id);

    FILE *f = fopen(fname, "w");
    if (f == NULL) {
        fprintf(stderr, "[q%u] Could not open %s for writing\n",
                queue_id, fname);
        return;
    }

    fprintf(f, "{\n");

    fprintf(f, "  \"queue_id\": %u,\n", queue_id);
    fprintf(f, "  \"nb_tx_desc\": %u,\n", nb_tx_desc);
    fprintf(f, "  \"burst_size\": %u,\n", burst_size);
    fprintf(f, "  \"timer_hz\": %" PRIu64 ",\n", rte_get_tsc_hz());

    fprintf(f, "  \"samples\": %" PRIu64 ",\n", qs->samples);
    fprintf(f, "  \"recorded_samples\": %" PRIu64 ",\n",
            recorded_samples);

    fprintf(f, "  \"tx_pkts\": %" PRIu64 ",\n", qs->tx_pkts);
    fprintf(f, "  \"tx_bytes\": %" PRIu64 ",\n", qs->tx_bytes);
    fprintf(f, "  \"app_discarded\": %" PRIu64 ",\n",
            qs->app_discarded);

    fprintf(f, "  \"occupancy_polls\": %" PRIu64 ",\n",
            qs->used_polls);
    fprintf(f, "  \"polls_per_sample\": %.6f,\n",
            qs->samples
                ? (double)qs->used_polls / (double)qs->samples
                : 0.0);

    fprintf(f, "  \"offered_pkts\": %" PRIu64 ",\n", offered_pkts);
    fprintf(f, "  \"occupancy_gated\": %" PRIu64 ",\n",
            qs->occupancy_gated);
    fprintf(f, "  \"gating_pct\": %.6f,\n", gating_pct);

    fprintf(f, "  \"attempted_pkts\": %" PRIu64 ",\n",
            attempted_pkts);
    fprintf(f, "  \"tx_not_accepted\": %" PRIu64 ",\n",
            qs->tx_not_accepted);
    fprintf(f, "  \"rejection_pct\": %.6f,\n", rejection_pct);
    fprintf(f, "  \"tx_pkts_per_second\": %.2f,\n",
            tx_pkts_per_second);

    fprintf(f, "  \"reject_events\": %" PRIu64 ",\n",
            qs->reject_events);

    if (qs->reject_events) {
        fprintf(f, "  \"first_reject_sample\": %" PRIu64 ",\n",
                qs->first_reject_sample);
        fprintf(f, "  \"last_reject_sample\": %" PRIu64 ",\n",
                qs->last_reject_sample);
    } else {
        fprintf(f, "  \"first_reject_sample\": null,\n");
        fprintf(f, "  \"last_reject_sample\": null,\n");
    }

    fprintf(f, "  \"last_used\": %u,\n", qs->last_used);
    fprintf(f, "  \"min_used\": %u,\n", qs->min_used);
    fprintf(f, "  \"max_used\": %u,\n", qs->max_used);
    fprintf(f, "  \"avg_used\": %.6f,\n",
            qs->used_polls
                ? (double)qs->sum_used / (double)qs->used_polls
                : 0.0);

    fprintf(f, "  \"cycles_count\": %" PRIu64 ",\n",
            qs->cycles_count);
    fprintf(f, "  \"cycles_tx\": %" PRIu64 ",\n",
            qs->cycles_tx);
    fprintf(f, "  \"cycles_total\": %" PRIu64 ",\n",
            qs->cycles_total);

    fprintf(f, "  \"avg_cycles_count\": %.6f,\n",
            qs->used_polls
                ? (double)qs->cycles_count / (double)qs->used_polls
                : 0.0);
    fprintf(f, "  \"avg_cycles_tx\": %.6f,\n",
            qs->samples
                ? (double)qs->cycles_tx / (double)qs->samples
                : 0.0);
    fprintf(f, "  \"avg_cycles_total\": %.6f,\n",
            qs->samples
                ? (double)qs->cycles_total / (double)qs->samples
                : 0.0);

    /*
     * Store histograms as:
     *
     *   [{"value": 32, "count": 100}, ...]
     *
     * rather than 4096 mostly-zero entries.
     */
    fprintf(f, "  \"used_histogram\": [\n");

    bool first = true;
    for (uint32_t i = 0; i < USED_HIST_MAX; i++) {
        if (used_hist[i] == 0)
            continue;

        fprintf(f,
                "%s    {\"value\": %u, \"count\": %" PRIu64 "}",
                first ? "" : ",\n",
                i, used_hist[i]);

        first = false;
    }

    fprintf(f, "\n  ],\n");

    fprintf(f, "  \"watermark_histogram\": [\n");

    first = true;
    for (uint32_t i = 0; i < USED_HIST_MAX; i++) {
        if (watermark_hist[i] == 0)
            continue;

        fprintf(f,
                "%s    {\"value\": %u, \"count\": %" PRIu64 "}",
                first ? "" : ",\n",
                i, watermark_hist[i]);

        first = false;
    }

    fprintf(f, "\n  ]\n");
    fprintf(f, "}\n");

    fclose(f);
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
  /*

  txconf.tx_thresh.pthresh = 32;
  txconf.tx_thresh.hthresh = 0;
  txconf.tx_thresh.wthresh = 0;

  txconf.tx_rs_thresh   = 1;
  txconf.tx_free_thresh = 1;
  */

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

static inline uint64_t ms_to_tsc(uint64_t ms) {
  uint64_t hz = rte_get_tsc_hz();
  return (hz / 1000) * ms + ((hz % 1000) * ms) / 1000;
}

static inline void spin_until_tsc(uint64_t deadline) {
  while (!force_quit && rte_rdtsc() < deadline)
    rte_pause();
}

/*
 * Execute one offered-load iteration. */
#ifdef COMP // {
static inline void tx_iteration(struct worker_ctx *ctx, struct comp_state *dpab,
                                struct sample_record *s, struct queue_stats *qs,
                                uint64_t used_hist[USED_HIST_MAX],
                                uint64_t watermark_hist[USED_HIST_MAX],
                                bool collect_stats, uint64_t sample_idx) {
  struct sample_record scratch;
  if (s == NULL)
    s = &scratch;
  memset(s, 0, sizeof(*s));

  uint64_t t0 = rte_rdtsc();
  int used = rte_eth_tx_queue_count(port_id, ctx->queue_id);
  uint64_t t1 = rte_rdtsc();

  bool have_used = (used >= 0);
  uint32_t raw_used = have_used ? (uint32_t)used : 0;

  if (have_used) {
    comp_observe(dpab, raw_used);

    if (collect_stats) {
      if (raw_used < USED_HIST_MAX)
        used_hist[raw_used]++;

      qs->last_used = (uint16_t)raw_used;
      if (qs->used_polls == 0) {
        qs->min_used = qs->max_used = (uint16_t)raw_used;
      } else {
        if (raw_used < qs->min_used)
          qs->min_used = (uint16_t)raw_used;
        if (raw_used > qs->max_used)
          qs->max_used = (uint16_t)raw_used;
      }
      qs->sum_used += raw_used;
      qs->used_polls++;
    }
  }
  s->used = have_used ? raw_used : UINT32_MAX;

  uint16_t requested = burst_size;
  // uint16_t to_send =
  //     have_used ? comp_admit(dpab, raw_used, requested) : requested;
  uint16_t to_send = requested;

  s->requested = requested;
  s->to_send = to_send;
  s->occupancy_gated = requested - to_send;

  struct rte_mbuf *bufs[MAX_PKT_BURST];
  uint16_t sent = 0;

  if (to_send > 0 &&
      rte_pktmbuf_alloc_bulk(ctx->mbuf_pool, bufs, to_send) == 0) {

    for (uint16_t i = 0; i < to_send; i++)
      fill_dummy_packet(bufs[i]);

    uint64_t t2 = rte_rdtsc();
    sent = rte_eth_tx_burst(port_id, ctx->queue_id, bufs, to_send);
    uint64_t t3 = rte_rdtsc();
    s->cycles_tx = t3 - t2;

    for (uint16_t i = sent; i < to_send; i++)
      rte_pktmbuf_free(bufs[i]);
  }

  s->sent = sent;
  s->tx_not_accepted = to_send - sent;
  s->cycles_count = t1 - t0;

  if (s->tx_not_accepted > 0) {

    qs->reject_events++;

    if (qs->first_reject_sample == UINT64_MAX)
      qs->first_reject_sample = sample_idx;

    qs->last_reject_sample = sample_idx;
  }

  if (have_used) {
    comp_feedback(dpab, raw_used, to_send, sent);

    if (sent < to_send) {
      printf("[sample=%" PRIu64 "] reject: "
             "used=%u attempted=%u sent=%u "
             "step=%u high_wm=%u wm_valid=%u\n",
             sample_idx, used, to_send, sent, dpab->observed_step,
             dpab->high_wm, dpab->wm_valid);
    }
    watermark_hist[dpab->high_wm]++;
  }

  if (collect_stats) {
    qs->tx_pkts += sent;
    qs->tx_bytes += (uint64_t)sent * PKT_LEN;
    qs->tx_not_accepted += s->tx_not_accepted;
    qs->app_discarded += s->tx_not_accepted;
    qs->occupancy_gated += s->occupancy_gated;
    qs->cycles_count += s->cycles_count;
    qs->cycles_tx += s->cycles_tx;
    qs->samples++;
  }
}
#endif // }

#ifdef BQL // {
#define PAB_INTERVAL_US 20
static inline void tx_iteration(struct worker_ctx *ctx, struct pab_bql *cpab,
                                struct sample_record *s, struct queue_stats *qs,
                                uint64_t used_hist[USED_HIST_MAX],
                                uint64_t watermark_hist[USED_HIST_MAX],
                                bool collect_stats, uint64_t sample_idx) {
  struct sample_record scratch;
  if (s == NULL)
    s = &scratch;
  memset(s, 0, sizeof(*s));

  const uint16_t requested = burst_size;
  uint64_t iter_start = rte_rdtsc();
  uint64_t now_cycles = rte_get_timer_cycles();

  if (now_cycles - cpab->last_tick_cycles >= cpab->tick_cycles) {
    uint64_t cleanup_start = rte_rdtsc();
    int freed = rte_eth_tx_done_cleanup(port_id, ctx->queue_id, 0);
    uint64_t cleanup_end = rte_rdtsc();
    s->cycles_count = cleanup_end - cleanup_start;

    if (freed > 0) {
      uint64_t completed = cpab->num_completed + (uint64_t)freed;
          cpab->num_completed =
		          completed > cpab->num_queued
			              ? cpab->num_queued
				                  : completed;

      uint64_t inflight = cpab->num_queued - cpab->num_completed;

      if (inflight == 0) {
      	cpab->limit += PAB_GROW_STEP;
	if (cpab->limit > nb_tx_desc)
		cpab->limit = nb_tx_desc;
      } else if (inflight >= cpab->limit) {
      	cpab->limit = (cpab->limit > PAB_GROW_STEP) ? cpab->limit - PAB_GROW_STEP : PAB_LIMIT_MIN;

	if (cpab->limit < PAB_LIMIT_MIN)
		cpab->limit = PAB_LIMIT_MIN;
      }

      cpab->last_tick_cycles = now_cycles;
    }

    uint64_t inflight = cpab->num_queued - cpab->num_completed;

    cpab->last_tick_cycles = now_cycles;
  }

  uint64_t inflight_now = cpab->num_queued - cpab->num_completed;
  uint32_t bql_space = (cpab->limit > inflight_now) 
	  ? (uint32_t)(cpab->limit - inflight_now)
	  : 0;

  uint16_t to_send = RTE_MIN(bql_space, burst_size);

  s->used = inflight_now > UINT32_MAX ? UINT32_MAX : (uint32_t)inflight_now;
  s->space = inflight_now;
  s->requested = requested;
  s->to_send = to_send;
  s->occupancy_gated = requested - to_send;

  if (collect_stats) {
    if (s->used < USED_HIST_MAX)
      used_hist[s->used]++;
    if (cpab->limit < USED_HIST_MAX)
      watermark_hist[cpab->limit]++;

    qs->last_used = (uint16_t)RTE_MIN(s->used, (uint32_t)UINT16_MAX);
    if (qs->used_polls == 0) {
      qs->min_used = qs->max_used = qs->last_used;
    } else {
      if (qs->last_used < qs->min_used)
        qs->min_used = qs->last_used;
      if (qs->last_used > qs->max_used)
        qs->max_used = qs->last_used;
    }
    qs->sum_used += s->used;
    qs->used_polls++;
  }

  struct rte_mbuf *bufs[MAX_PKT_BURST];
  uint16_t sent = 0;

  if (!force_quit && to_send > 0 &&
      rte_pktmbuf_alloc_bulk(ctx->mbuf_pool, bufs, to_send) == 0) {

    for (uint16_t i = 0; i < to_send; i++)
      fill_dummy_packet(bufs[i]);


    uint64_t tx_start = rte_rdtsc();
    sent = rte_eth_tx_burst(port_id, ctx->queue_id, bufs, to_send);
    uint64_t tx_end = rte_rdtsc();
    s->cycles_tx = tx_end - tx_start;

    /* Only packets accepted by the PMD become BQL in-flight packets. */
    cpab->num_queued += sent;

    for (uint16_t i = sent; i < to_send; i++)
      rte_pktmbuf_free(bufs[i]);
  }

  s->sent = sent;
  s->tx_not_accepted = to_send - sent;
  s->cycles_total = rte_rdtsc() - iter_start;

  if (s->tx_not_accepted > 0) {
    qs->reject_events++;
    if (qs->first_reject_sample == UINT64_MAX)
      qs->first_reject_sample = sample_idx;
    qs->last_reject_sample = sample_idx;
  }

  if (sent < to_send) {
    uint64_t observed_full = inflight_now + sent;

    if (observed_full < cpab->limit) {
      cpab->limit = observed_full < PAB_LIMIT_MIN ? PAB_LIMIT_MIN
                                                  : (uint32_t)observed_full;
    }

  }

  if (collect_stats) {
    qs->tx_pkts += sent;
    qs->tx_bytes += (uint64_t)sent * PKT_LEN;
    qs->tx_not_accepted += s->tx_not_accepted;
    qs->app_discarded += s->tx_not_accepted;
    qs->occupancy_gated += s->occupancy_gated;
    qs->cycles_count += s->cycles_count;
    qs->cycles_tx += s->cycles_tx;
    qs->cycles_total += s->cycles_total;
    qs->samples++;
  }
}
#endif // }

static int tx_worker_main(void *arg) {
  struct worker_ctx *ctx = (struct worker_ctx *)arg;
  uint16_t queue_id = ctx->queue_id;
  uint64_t recorded_samples = 0;
  struct queue_stats *qs = &qstats[queue_id];
  uint64_t used_hist[USED_HIST_MAX] = {0};
  uint64_t watermark_hist[USED_HIST_MAX] = {0};
#ifdef COMP
  struct comp_state dpab = {0};
#endif
#ifdef BQL
  struct pab_bql cpab = {0};
  cpab.num_queued = 0;
  cpab.num_completed = 0;
  cpab.limit = burst_size;
  cpab.last_tick_cycles = rte_get_timer_cycles();
#endif

  qs->first_reject_sample = UINT64_MAX;

  /* Barrier 1: all workers are alive before any one of them starts traffic. */
  uint32_t ready = __atomic_add_fetch(&sync_workers_ready, 1, __ATOMIC_ACQ_REL);
  if (ready == sync_n_workers) {
    uint64_t now = rte_rdtsc();
    global_warmup_start_tsc = now + ms_to_tsc(SYNC_LEAD_MS);
    global_warmup_end_tsc = global_warmup_start_tsc + ms_to_tsc(warmup_ms);
    __atomic_store_n(&sync_warmup_schedule_ready, 1, __ATOMIC_RELEASE);
  }

  while (!force_quit &&
         !__atomic_load_n(&sync_warmup_schedule_ready, __ATOMIC_ACQUIRE))
    rte_pause();

  spin_until_tsc(global_warmup_start_tsc);

  while (!force_quit && rte_rdtsc() < global_warmup_end_tsc)
    ;
  // tx_iteration(ctx, &dpab, NULL, qs, used_hist, false);

  /*
   * Barrier 2: no queue begins measurement until every queue has left the
   * warm-up loop. The last worker publishes one shared start/end deadline.
   */
  uint32_t warmed = __atomic_add_fetch(&sync_warmup_done, 1, __ATOMIC_ACQ_REL);
  if (warmed == sync_n_workers) {
    uint64_t now = rte_rdtsc();
    global_start_tsc = now + ms_to_tsc(SYNC_LEAD_MS);
    global_end_tsc = global_start_tsc + ms_to_tsc(measure_ms);
    __atomic_store_n(&sync_measure_schedule_ready, 1, __ATOMIC_RELEASE);
  }

  while (!force_quit &&
         !__atomic_load_n(&sync_measure_schedule_ready, __ATOMIC_ACQUIRE))
    rte_pause();

  spin_until_tsc(global_start_tsc);
#ifdef COMP
  memset(&dpab, 0, sizeof(dpab)); // reset state
#endif

  /*
   * Timed measurement: all queues use the same global_end_tsc. Reaching the
   * raw-record capacity never stops traffic or statistics; it only truncates
   * the per-iteration binary record stream.
   */
  uint64_t tsc_hz = rte_get_tsc_hz();

#ifdef BQL
  uint64_t interval_cycles =
	      (tsc_hz / 1000000ULL) * PAB_INTERVAL_US;
#endif

  uint64_t next_tick = global_start_tsc;

  while (!force_quit && rte_rdtsc() < global_end_tsc) {
    struct sample_record *s = NULL;
    if (recorded_samples < target_samples)
      s = &ctx->samples[recorded_samples];

#ifdef COMP
    tx_iteration(ctx, &dpab, s, qs, used_hist, watermark_hist, true,
                 recorded_samples);
#endif
#ifdef BQL
    next_tick += interval_cycles;

    spin_until_tsc(next_tick);

    tx_iteration(ctx, &cpab, s, qs, used_hist, watermark_hist, true,
                 recorded_samples);
#endif

    if (recorded_samples < target_samples)
      recorded_samples++;
  }

  uint64_t offered_pkts = qs->samples * (uint64_t)burst_size;
  uint64_t attempted_pkts = offered_pkts >= qs->occupancy_gated
                                ? offered_pkts - qs->occupancy_gated
                                : 0;

  double gating_pct =
      offered_pkts ? 100.0 * (double)qs->occupancy_gated / (double)offered_pkts
                   : 0.0;

  double rejection_pct = attempted_pkts ? 100.0 * (double)qs->tx_not_accepted /
                                              (double)attempted_pkts
                                        : 0.0;

  double measure_seconds =
      (double)(global_end_tsc - global_start_tsc) / (double)rte_get_timer_hz();

  double tx_pkts_per_second =
      measure_seconds > 0.0 ? (double)qs->tx_pkts / measure_seconds : 0.0;

  printf("reject_events       : %" PRIu64 "\n", qs->reject_events);

  if (qs->reject_events > 0) {
    printf("first_reject_sample : %" PRIu64 "\n", qs->first_reject_sample);
    printf("last_reject_sample  : %" PRIu64 "\n", qs->last_reject_sample);
  } else {
    printf("first_reject_sample : none\n");
    printf("last_reject_sample  : none\n");
  }

  printf("\n"
         "========== Queue %u benchmark ==========\n"
         "samples             : %" PRIu64 "\n"
         "recorded_samples    : %" PRIu64 "\n"
         "tx_pkts             : %" PRIu64 "\n"
         "tx_bytes            : %" PRIu64 "\n"
         "app_discarded       : %" PRIu64 "\n"
         "\n"
         "occupancy_polls     : %" PRIu64 "\n"
         "polls_per_sample    : %.2f\n"
         "\n"
         "occupancy_gated     : %" PRIu64 "\n"
         "gating_pct          : %.6f\n"
         "attempted_pkts      : %" PRIu64 "\n"
         "tx_not_accepted     : %" PRIu64 "\n"
         "rejection_pct       : %.6f\n"
         "tx_pkts_per_second  : %.2f\n"
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
         queue_id, qs->samples, recorded_samples, qs->tx_pkts, qs->tx_bytes,
         qs->app_discarded, qs->used_polls,
         qs->samples ? (double)qs->used_polls / (double)qs->samples : 0.0,
         qs->occupancy_gated, gating_pct, attempted_pkts, qs->tx_not_accepted,
         rejection_pct, tx_pkts_per_second, qs->last_used, qs->min_used,
         qs->max_used,
         qs->used_polls ? (double)qs->sum_used / (double)qs->used_polls : 0.0,
         qs->cycles_count, qs->cycles_tx, qs->cycles_total,
         qs->used_polls ? (double)qs->cycles_count / (double)qs->used_polls
                        : 0.0,
         qs->samples ? (double)qs->cycles_tx / (double)qs->samples : 0.0,
         qs->samples ? (double)qs->cycles_total / (double)qs->samples : 0.0);

  if (qs->samples > recorded_samples) {
    printf("[q%u] WARNING: raw sample capacity reached: stored %" PRIu64
           " of %" PRIu64 " measurement iterations. Increase -c to keep "
           "the complete time series.\n",
           queue_id, recorded_samples, qs->samples);
  }

  printf("\nTX queue-count histogram:\n");
  for (uint32_t i = 0; i < USED_HIST_MAX; i++) {
    if (used_hist[i] != 0) {
      printf("queue %d  used=%3u : %" PRIu64 " (%.4f%%)\n", queue_id, i,
             used_hist[i],
             qs->used_polls
                 ? 100.0 * (double)used_hist[i] / (double)qs->used_polls
                 : 0.0);
    }
  }

  printf("\nhigh_wm histogram:\n");
  for (uint32_t i = 0; i < USED_HIST_MAX; i++) {
    if (watermark_hist[i] != 0) {
      printf("queue %d  watermark=%3u : %" PRIu64 " (%.4f%%)\n", queue_id, i,
             watermark_hist[i],
             qs->used_polls
                 ? 100.0 * (double)watermark_hist[i] / (double)qs->used_polls
                 : 0.0);
    }
  }

write_queue_json(queue_id,
                 qs,
                 recorded_samples,
                 offered_pkts,
                 attempted_pkts,
                 gating_pct,
                 rejection_pct,
                 tx_pkts_per_second,
                 used_hist,
                 watermark_hist);

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
        .num_records = recorded_samples,
        .nb_tx_desc = nb_tx_desc,
        .burst_size = burst_size,
        .timer_hz = rte_get_tsc_hz(),
    };

    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(qs, sizeof(*qs), 1, f);
    fwrite(ctx->samples, sizeof(struct sample_record), recorded_samples, f);
    fclose(f);

    printf("[q%u] wrote %" PRIu64 " raw samples + queue stats to %s "
           "(record=%zu bytes, stats=%zu bytes)\n",
           queue_id, recorded_samples, fname, sizeof(struct sample_record),
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
  sync_n_workers = n_workers;

  struct rte_mempool *mbuf_pool =
      rte_pktmbuf_pool_create("MBUF_POOL", MBUF_POOL_SIZE, MBUF_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

  if (port_init(port_id, mbuf_pool) != 0)
    rte_exit(EXIT_FAILURE, "Port init failed\n");

  // register_telemetry();

  printf("Port %u up. workers=%u nb_tx_q=%u nb_tx_desc=%u burst=%u "
         "method=%s shaped_rate=%" PRIu64 " Bps pacing_ns=%" PRIu64 " "
         "warmup_ms=%" PRIu64 " measure_ms=%" PRIu64 " raw_capacity=%" PRIu64
         "\n",
         port_id, n_workers, nb_tx_q, nb_tx_desc, burst_size,
         use_tm ? "rte_tm" : "legacy", shaped_rate_bps, pacing_ns, warmup_ms,
         measure_ms, target_samples);

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

  printf("Synchronized windows: warmup=[%" PRIu64 ", %" PRIu64 ") "
         "measure=[%" PRIu64 ", %" PRIu64 ") measure_cycles=%" PRIu64 "\n",
         global_warmup_start_tsc, global_warmup_end_tsc, global_start_tsc,
         global_end_tsc, global_end_tsc - global_start_tsc);

  for (unsigned i = 0; i < n_workers; i++)
    rte_free(worker_ctx[i].samples);

  rte_eth_dev_stop(port_id);
  rte_eth_dev_close(port_id);
  rte_eal_cleanup();
  return 0;
}
