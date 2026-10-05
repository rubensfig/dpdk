/*
 * tx_shaper_baseline: microbenchmark for software--NIC transmit controllers.
 *
 * Each worker lcore owns one Tx queue and, in a loop, requests a burst of
 * B_req synthetic packets. A per-queue controller computes a budget B_cap,
 * the worker submits B_tx = min(B_req, B_cap) with rte_eth_tx_burst(), and
 * the controller is updated with B_sent. This mirrors the structure of the
 * algorithms in the paper (budget -> transmit -> update).
 *
 * The controller is selected at compile time (meson.build, tx_controller):
 *
 *   none  Uncoordinated: B_cap = B_req, rejected packets are dropped.
 *   pab   Priority-Aware Backpressure: retry buffer of PAB_RETRY_MAX packets,
 *         retried first; B_cap = free space in the retry buffer.
 *   rej   REJ (paper appendix): window W from transmission outcomes only.
 *   cbc   CBC (paper Algorithm 1): B_cap = N_desc - (Q - C), with C from
 *         rte_eth_tx_done_cleanup() every T_poll.
 *   qbc   QBC (paper Algorithm 2): queue state U from
 *         rte_eth_tx_queue_count(); every burst is capped at the learned
 *         congestion boundary, B_cap = H - U.
 *
 * Packets withheld by the controller (gated) and packets rejected by the NIC
 * are freed by the benchmark, except under PAB, which retries rejected ones.
 *
 * Usage example (rte_tm shaping, 4 worker lcores -> 4 Tx queues):
 *   ./tx_shaper_baseline -l 0,1,2,3,4 -- -p 0 -n 1024 -b 3125000000 -m 64 \
 *       -c 5000000 -o samples
 *
 * App args (after --):
 *   -p PORT_ID     port to use (default 0)
 *   -n NB_DESC     nb_tx_desc, Tx ring depth (default 256)
 *   -b RATE        shaped rate via rte_tm in BYTES/s (default 0 = no shaping)
 *   -m BURST       packets requested per iteration, B_req (default 32,
 *                  clamped to [1, MAX_PKT_BURST])
 *   -c COUNT       maximum raw sample records stored per queue. Statistics
 *                  cover the whole measurement window even if this is hit.
 *   -w WARMUP_MS   common warm-up duration in ms (default 100)
 *   -d MEASURE_MS  common measurement duration in ms (default 800)
 *   -o OUTFILE     base name; each worker writes <OUTFILE>_q<N>.bin/.json
 *   -T TYPE        transient during [50, 150) ms of the measurement:
 *                  0 pause, 1 on/off duty cycle, 2 small bursts (default 0)
 *   -D PERIOD_MS   on/off period of transient type 1 (default 1)
 *   -I POLL_US     CBC only: completion polling interval T_poll (default 10)
 *   -A STEP        REJ only: window increase A (default 8)
 *   -K STREAK      REJ only: full bursts K before increasing (default 32)
 *
 * Multi-core: every non-main lcore passed via EAL "-l" becomes a Tx worker;
 * worker i owns Tx queue i. With a single lcore, the main lcore transmits.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pause.h>
#include <rte_tm.h>

#if defined(NONE) + defined(PAB) + defined(REJ) + defined(CBC) + defined(QBC) != 1
#error "define exactly one of NONE, PAB, REJ, CBC, QBC (see meson.build)"
#endif

#if defined(NONE)
#define MECHANISM "NONE"
#elif defined(PAB)
#define MECHANISM "PAB"
#elif defined(REJ)
#define MECHANISM "REJ"
#elif defined(CBC)
#define MECHANISM "CBC"
#else
#define MECHANISM "QBC"
#endif

#define MAX_PKT_BURST 4096
#define DEFAULT_BURST 32
#define MBUF_POOL_SIZE 131072
#define MBUF_CACHE_SIZE 256
#define PKT_LEN 512
#define MAX_TX_QUEUES 64
#define USED_HIST_MAX 8192

/* Transient window, relative to the start of the measurement. */
#define TRANSIENT_START_MS 50u
#define TRANSIENT_LEN_MS 100u
#define TRANSIENT_SMALL_BURST 32u

/* ---- CLI-configurable parameters ---- */
static uint16_t port_id = 0;
static uint16_t nb_tx_q = 1; /* derived from the worker lcore count */
static uint16_t nb_tx_desc = 256;
static uint16_t burst_size = DEFAULT_BURST;
static uint64_t shaped_rate_bps = 0; /* rte_tm, bytes/s, 0 = disabled */
static uint32_t transient_type = 0;  /* 0 pause, 1 duty cycle, 2 small bursts */
static uint32_t period_ms = 1;
static uint64_t target_samples = 1000000;
static uint64_t warmup_ms = 100;
static uint64_t measure_ms = 800;
static char outfile_base[256] = "samples";

#ifdef CBC
static uint32_t cbc_poll_us = 10u; /* T_poll */
#endif

#ifdef REJ
static uint32_t rej_add_step = 8u;     /* A */
static uint32_t rej_grow_streak = 32u; /* K */
#define REJ_MIN 1u
#endif

#ifdef PAB
#define PAB_RETRY_MAX 512 /* retry buffer capacity, power of two */
#if (PAB_RETRY_MAX & (PAB_RETRY_MAX - 1)) != 0
#error "PAB_RETRY_MAX must be a power of two"
#endif
#endif

/* ---- Synchronisation of the workers' warm-up and measurement windows ----
 *
 * Two worker-only barriers:
 *   1) all workers ready -> last worker publishes the common warm-up window
 *   2) all workers finish warm-up -> last worker publishes the measurement
 *      window
 */
#define SYNC_LEAD_MS 10u

static uint32_t sync_n_workers;
static uint32_t sync_workers_ready;
static uint32_t sync_warmup_done;
static uint32_t sync_warmup_schedule_ready;
static uint32_t sync_measure_schedule_ready;
static uint64_t global_warmup_start_tsc;
static uint64_t global_warmup_end_tsc;
static uint64_t global_start_tsc;
static uint64_t global_end_tsc;

/* TM node ids: arbitrary, unique within the hierarchy */
#define SHAPER_PROFILE_1 1
#define NODE_1000 1000
#define NODE_900 900
#define NODE_800 800
#define NODE_700 700

static volatile int force_quit = 0;

/* ---- Output formats (layouts unchanged; parsed by the analysis scripts) */
#define SAMPLE_FILE_MAGIC 0x5458424D /* "TXBM" */
#define SAMPLE_FILE_VERSION 1

struct queue_stats {
  uint64_t samples; /* measurement iterations */

  uint16_t last_used;
  uint16_t min_used;
  uint16_t max_used;
  uint16_t reserved0;

  uint64_t sum_used;

  uint64_t tx_pkts; /* accepted by the NIC, including PAB retries */
  uint64_t tx_bytes;

  uint64_t tx_drops; /* unused, kept for the file layout */

  uint64_t occupancy_gated; /* B_req - B_tx */
  uint64_t tx_not_accepted; /* B_tx - B_sent (fresh packets) */
  uint64_t app_discarded;   /* mbufs freed by the benchmark */

  uint64_t used_polls; /* iterations with a valid controller signal */

  uint64_t reject_events;
  uint64_t first_reject_sample;
  uint64_t last_reject_sample;

  uint64_t cycles_count; /* feedback: tx_queue_count / tx_done_cleanup */
  uint64_t cycles_tx;    /* rte_eth_tx_burst */
  uint64_t cycles_total; /* whole iteration */
};

static struct queue_stats qstats[MAX_TX_QUEUES];

/*
 * One record per iteration. Controller-specific fields:
 *   used           NONE: 0; PAB: retry-buffer occupancy; REJ: full-burst
 *                  streak s; CBC: Q - C; QBC: U (UINT32_MAX if unavailable)
 *   space          PAB: retry-buffer space; CBC: B_cap
 *   limit          NONE, CBC: N_desc; PAB: retry-buffer capacity
 *   freed          CBC: completions returned by this iteration's poll
 *   high_wm        REJ: window W; QBC: H (before the update)
 *   observed_step  REJ: A; QBC: Delta
 *   wm_valid       REJ: W > 0; QBC: H defined
 */
struct sample_record {
  uint32_t used;
  uint32_t space;

  uint32_t limit;
  uint32_t freed;

  uint32_t high_wm;
  uint32_t observed_step;
  uint8_t wm_valid;
  uint8_t reserved1[3];

  uint16_t requested; /* B_req */
  uint16_t to_send;   /* B_tx */
  uint16_t sent;      /* B_sent */

  uint16_t occupancy_gated;
  uint16_t tx_not_accepted;
  uint16_t reserved0;

  uint64_t cycles_count;
  uint64_t cycles_tx;
  uint64_t cycles_total;

  uint64_t tsc;
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

static inline void hist_inc(uint64_t hist[USED_HIST_MAX], uint64_t value) {
  hist[RTE_MIN(value, (uint64_t)USED_HIST_MAX - 1)]++;
}

/* ======================================================================
 * Controllers
 *
 * Each controller provides:
 *   ctrl_init(c)
 *   ctrl_budget(c, queue, B_req, s, &obs) -> B_cap
 *       reads feedback and fills the controller fields of the record;
 *       obs.used is the value recorded in the "used" histogram.
 *   ctrl_keep_rejected(c, pkts, n) -> packets kept (PAB only)
 *   ctrl_update(c, s, B_tx, B_sent, watermark_hist)
 * ====================================================================== */

struct ctrl_obs {
  uint32_t used;
  bool have_used;
  uint16_t extra_sent; /* PAB: retried packets accepted this iteration */
};

/* ---- Uncoordinated ---------------------------------------------------- */
#ifdef NONE

struct ctrl {
  int unused;
};

static inline void ctrl_init(struct ctrl *c) { memset(c, 0, sizeof(*c)); }

static inline uint32_t ctrl_budget(struct ctrl *c, uint16_t queue,
                                   uint16_t b_req, struct sample_record *s,
                                   struct ctrl_obs *o) {
  RTE_SET_USED(c);
  RTE_SET_USED(queue);
  s->limit = nb_tx_desc;
  o->used = 0;
  o->have_used = true;
  return b_req;
}

static inline uint16_t ctrl_keep_rejected(struct ctrl *c,
                                          struct rte_mbuf **pkts, uint16_t n) {
  RTE_SET_USED(c);
  RTE_SET_USED(pkts);
  RTE_SET_USED(n);
  return 0;
}

static inline void ctrl_update(struct ctrl *c, struct sample_record *s,
                               uint16_t b_tx, uint16_t b_sent,
                               uint64_t wm_hist[USED_HIST_MAX]) {
  RTE_SET_USED(c);
  RTE_SET_USED(s);
  RTE_SET_USED(b_tx);
  RTE_SET_USED(b_sent);
  RTE_SET_USED(wm_hist);
}

#endif /* NONE */

/* ---- PAB: retry buffer ------------------------------------------------ */
#ifdef PAB

/*
 * Every iteration: 1) retry buffered packets first (at most one burst);
 * 2) B_cap = free space in the retry buffer; 3) transmit fresh packets;
 * 4) buffer fresh packets rejected by the NIC.
 */
struct ctrl {
  struct rte_mbuf *pkts[PAB_RETRY_MAX];
  uint32_t head;
  uint32_t tail;
  uint32_t cnt;
};

static inline void ctrl_init(struct ctrl *c) { memset(c, 0, sizeof(*c)); }

static inline uint32_t ctrl_budget(struct ctrl *c, uint16_t queue,
                                   uint16_t b_req, struct sample_record *s,
                                   struct ctrl_obs *o) {
  struct rte_mbuf *retry[MAX_PKT_BURST];
  uint16_t n = (uint16_t)RTE_MIN(c->cnt, (uint32_t)burst_size);

  for (uint16_t i = 0; i < n; i++)
    retry[i] = c->pkts[(c->head + i) & (PAB_RETRY_MAX - 1u)];

  if (n > 0) {
    uint64_t t0 = rte_rdtsc();
    uint16_t sent = rte_eth_tx_burst(port_id, queue, retry, n);
    s->cycles_tx += rte_rdtsc() - t0;

    c->head = (c->head + sent) & (PAB_RETRY_MAX - 1u);
    c->cnt -= sent;
    o->extra_sent = sent;
  }

  uint32_t space = PAB_RETRY_MAX - c->cnt;

  s->used = c->cnt;
  s->space = space;
  s->limit = PAB_RETRY_MAX;
  o->used = c->cnt;
  o->have_used = true;

  return RTE_MIN((uint32_t)b_req, space);
}

static inline uint16_t ctrl_keep_rejected(struct ctrl *c,
                                          struct rte_mbuf **pkts, uint16_t n) {
  for (uint16_t i = 0; i < n; i++) {
    /* B_tx is capped by the free space, so this should not fire. */
    if (c->cnt >= PAB_RETRY_MAX) {
      rte_pktmbuf_free(pkts[i]);
      continue;
    }
    c->pkts[c->tail] = pkts[i];
    c->tail = (c->tail + 1u) & (PAB_RETRY_MAX - 1u);
    c->cnt++;
  }
  return n;
}

static inline void ctrl_update(struct ctrl *c, struct sample_record *s,
                               uint16_t b_tx, uint16_t b_sent,
                               uint64_t wm_hist[USED_HIST_MAX]) {
  RTE_SET_USED(s);
  if (b_sent < b_tx)
    hist_inc(wm_hist, c->cnt);
}

#endif /* PAB */

/* ---- REJ: outcome-based window (paper appendix) ----------------------- */
#ifdef REJ

struct ctrl {
  uint32_t window;         /* W */
  uint32_t success_streak; /* s */
};

static inline void ctrl_init(struct ctrl *c) {
  memset(c, 0, sizeof(*c));
  c->window = burst_size;
}

static inline uint32_t ctrl_budget(struct ctrl *c, uint16_t queue,
                                   uint16_t b_req, struct sample_record *s,
                                   struct ctrl_obs *o) {
  RTE_SET_USED(queue);
  RTE_SET_USED(b_req);
  s->used = c->success_streak;
  s->high_wm = c->window;
  s->observed_step = rej_add_step;
  s->wm_valid = c->window > 0;
  o->used = c->window;
  o->have_used = true;
  return c->window;
}

static inline uint16_t ctrl_keep_rejected(struct ctrl *c,
                                          struct rte_mbuf **pkts, uint16_t n) {
  RTE_SET_USED(c);
  RTE_SET_USED(pkts);
  RTE_SET_USED(n);
  return 0;
}

static inline void ctrl_update(struct ctrl *c, struct sample_record *s,
                               uint16_t b_tx, uint16_t b_sent,
                               uint64_t wm_hist[USED_HIST_MAX]) {
  RTE_SET_USED(s);

  if (b_tx == 0) { /* idle iteration */
    c->window = burst_size;
    c->success_streak = 0;
    return;
  }

  if (b_sent < b_tx) {
    hist_inc(wm_hist, c->window);
    c->window = RTE_MAX((uint32_t)b_sent, REJ_MIN);
    c->success_streak = 0;
    return;
  }

  if (++c->success_streak >= rej_grow_streak) {
    c->window = RTE_MIN(c->window + rej_add_step, (uint32_t)burst_size);
    c->success_streak = 0;
  }
}

#endif /* REJ */

/* ---- CBC: Completion-Based Capacity (paper Algorithm 1) --------------- */
#ifdef CBC

struct ctrl {
  uint64_t q; /* Q: packets accepted by the NIC */
  uint64_t c; /* C: completed packets */
  uint64_t last_poll_tsc;
  uint64_t poll_tsc; /* T_poll in TSC cycles */
  bool warned;
};

static inline void ctrl_init(struct ctrl *c) {
  memset(c, 0, sizeof(*c));
  c->poll_tsc = (rte_get_tsc_hz() * (uint64_t)cbc_poll_us) / 1000000ULL;
}

static inline uint32_t ctrl_budget(struct ctrl *c, uint16_t queue,
                                   uint16_t b_req, struct sample_record *s,
                                   struct ctrl_obs *o) {
  RTE_SET_USED(b_req);

  /* i) Process transmission completions every T_poll */
  uint64_t now = rte_rdtsc();
  if (now - c->last_poll_tsc >= c->poll_tsc) {
    int freed = rte_eth_tx_done_cleanup(port_id, queue, 0);
    s->cycles_count = rte_rdtsc() - now;
    c->last_poll_tsc = now;

    if (freed > 0) {
      c->c = RTE_MIN(c->c + (uint64_t)freed, c->q);
      s->freed = (uint32_t)freed;
    } else if (freed < 0 && !c->warned) {
      fprintf(stderr,
              "[q%u] rte_eth_tx_done_cleanup() failed (%d): CBC sees no "
              "completions and will stall after one ring's worth\n",
              queue, freed);
      c->warned = true;
    }
  }

  /* ii) Compute transmission budget */
  uint64_t u = c->q - c->c; /* U_CBC */
  uint32_t b_cap = u < nb_tx_desc ? (uint32_t)(nb_tx_desc - u) : 0;

  s->used = (uint32_t)RTE_MIN(u, (uint64_t)UINT32_MAX);
  s->space = b_cap;
  s->limit = nb_tx_desc;
  o->used = s->used;
  o->have_used = true;

  return b_cap;
}

static inline uint16_t ctrl_keep_rejected(struct ctrl *c,
                                          struct rte_mbuf **pkts, uint16_t n) {
  RTE_SET_USED(c);
  RTE_SET_USED(pkts);
  RTE_SET_USED(n);
  return 0;
}

/* iv) Update accepted work */
static inline void ctrl_update(struct ctrl *c, struct sample_record *s,
                               uint16_t b_tx, uint16_t b_sent,
                               uint64_t wm_hist[USED_HIST_MAX]) {
  RTE_SET_USED(s);
  RTE_SET_USED(b_tx);
  RTE_SET_USED(wm_hist);
  c->q += b_sent;
}

#endif /* CBC */

/* ---- QBC: Queue Occupancy-Based Capacity (paper Algorithm 2) ----------
 *
 *   U = rte_eth_tx_queue_count(); Delta = gcd of the non-zero changes of U
 *   B_cap = B_req      while H is undefined
 *         = 0          if U >= H
 *         = H - U      otherwise (every burst is capped at the boundary)
 *   partial transmit (once Delta > 0): H = min(H, U)
 *   full transmit:                     H = max(H, U + B_sent)
 *
 * Because every burst is capped at H - U, a full transmit gives
 * U + B_sent <= H: H rises only before the first rejection and is
 * non-increasing afterwards. Delta only delays the first update of H until
 * the queue state has been seen to move.
 */
#ifdef QBC

struct ctrl {
  uint32_t h;      /* H: congestion boundary */
  bool h_valid;    /* H defined (initially undefined: no bound) */
  uint32_t u_prev; /* U_prev */
  bool have_prev;
  uint32_t delta; /* Delta: gcd of observed non-zero changes of U */
  uint32_t u;     /* U_QBC of the current iteration */
  bool have_u;
  bool warned;
};

static inline uint32_t gcd_u32(uint32_t a, uint32_t b) {
  while (b) {
    uint32_t t = a % b;
    a = b;
    b = t;
  }
  return a;
}

static inline void ctrl_init(struct ctrl *c) { memset(c, 0, sizeof(*c)); }

static inline uint32_t ctrl_budget(struct ctrl *c, uint16_t queue,
                                   uint16_t b_req, struct sample_record *s,
                                   struct ctrl_obs *o) {
  /* i) Observe queue state */
  uint64_t t0 = rte_rdtsc();
  int q = rte_eth_tx_queue_count(port_id, queue);
  s->cycles_count = rte_rdtsc() - t0;

  s->high_wm = c->h;
  s->wm_valid = c->h_valid;

  if (q < 0) {
    /* No queue state: transmit uncontrolled, as before. */
    if (!c->warned) {
      fprintf(stderr,
              "[q%u] rte_eth_tx_queue_count() failed (%d): QBC runs "
              "without backpressure\n",
              queue, q);
      c->warned = true;
    }
    c->have_u = false;
    s->used = UINT32_MAX;
    s->observed_step = c->delta;
    return b_req;
  }

  uint32_t u = (uint32_t)q;
  if (c->have_prev && u != c->u_prev)
    c->delta = gcd_u32(c->delta, u > c->u_prev ? u - c->u_prev : c->u_prev - u);
  c->u_prev = u;
  c->have_prev = true;
  c->u = u;
  c->have_u = true;

  s->used = u;
  s->observed_step = c->delta;
  o->used = u;
  o->have_used = true;

  /* ii) Compute transmission budget */
  if (!c->h_valid)
    return b_req;
  if (u >= c->h)
    return 0;
  return c->h - u;
}

static inline uint16_t ctrl_keep_rejected(struct ctrl *c,
                                          struct rte_mbuf **pkts, uint16_t n) {
  RTE_SET_USED(c);
  RTE_SET_USED(pkts);
  RTE_SET_USED(n);
  return 0;
}

/* iv) Update congestion boundary */
static inline void ctrl_update(struct ctrl *c, struct sample_record *s,
                               uint16_t b_tx, uint16_t b_sent,
                               uint64_t wm_hist[USED_HIST_MAX]) {
  RTE_SET_USED(s);

  if (!c->have_u || b_tx == 0)
    return;

  if (b_sent < b_tx) {
    if (c->delta == 0) /* queue state not yet seen to move */
      return;
    c->h = c->h_valid ? RTE_MIN(c->h, c->u) : c->u;
    c->h_valid = true;
    hist_inc(wm_hist, c->h);
  } else {
    uint32_t v = c->u + b_sent;
    c->h = c->h_valid ? RTE_MAX(c->h, v) : v;
    c->h_valid = true;
  }
}

#endif /* QBC */

/* ======================================================================
 * One transmission opportunity: budget -> transmit -> update
 * ====================================================================== */
static inline void tx_iteration(struct worker_ctx *ctx, struct ctrl *c,
                                struct sample_record *s, struct queue_stats *qs,
                                uint64_t used_hist[USED_HIST_MAX],
                                uint64_t wm_hist[USED_HIST_MAX], uint64_t iter,
                                uint16_t requested, struct rte_mbuf **bufs) {
  struct sample_record scratch;
  if (s == NULL)
    s = &scratch;
  memset(s, 0, sizeof(*s));

  uint64_t iter_start = rte_rdtsc();
  s->tsc = iter_start;

  struct ctrl_obs o = {0};
  uint32_t b_cap = ctrl_budget(c, ctx->queue_id, requested, s, &o);
  uint16_t to_send = (uint16_t)RTE_MIN((uint32_t)requested, b_cap);

  s->requested = requested;
  s->to_send = to_send;
  s->occupancy_gated = requested - to_send;

  uint16_t sent = 0;
  if (to_send > 0) {
    uint64_t t0 = rte_rdtsc();
    sent = rte_eth_tx_burst(port_id, ctx->queue_id, bufs, to_send);
    s->cycles_tx += rte_rdtsc() - t0;
  }

  uint16_t kept = ctrl_keep_rejected(c, &bufs[sent], to_send - sent);
  for (uint16_t i = sent + kept; i < requested; i++)
    rte_pktmbuf_free(bufs[i]);

  s->sent = sent;
  s->tx_not_accepted = to_send - sent;

  ctrl_update(c, s, to_send, sent, wm_hist);

  s->cycles_total = rte_rdtsc() - iter_start;

  /* ---- accounting ---- */
  if (s->tx_not_accepted > 0) {
    qs->reject_events++;
    if (qs->first_reject_sample == UINT64_MAX)
      qs->first_reject_sample = iter;
    qs->last_reject_sample = iter;
  }

  if (o.have_used) {
    hist_inc(used_hist, o.used);
    qs->last_used = (uint16_t)RTE_MIN(o.used, (uint32_t)UINT16_MAX);
    if (qs->used_polls == 0) {
      qs->min_used = qs->max_used = qs->last_used;
    } else {
      qs->min_used = RTE_MIN(qs->min_used, qs->last_used);
      qs->max_used = RTE_MAX(qs->max_used, qs->last_used);
    }
    qs->sum_used += o.used;
    qs->used_polls++;
  }

  uint64_t accepted = (uint64_t)sent + o.extra_sent;
  qs->tx_pkts += accepted;
  qs->tx_bytes += accepted * PKT_LEN;
  qs->tx_not_accepted += s->tx_not_accepted;
  qs->occupancy_gated += s->occupancy_gated;
  qs->app_discarded += (uint64_t)requested - sent - kept;
  qs->cycles_count += s->cycles_count;
  qs->cycles_tx += s->cycles_tx;
  qs->cycles_total += s->cycles_total;
  qs->samples++;
}

/* ======================================================================
 * Setup
 * ====================================================================== */
static void parse_args(int argc, char **argv) {
  int opt;
  while ((opt = getopt(argc, argv, "p:n:b:m:c:o:w:d:T:D:I:A:K:")) != -1) {
    switch (opt) {
    case 'p':
      port_id = (uint16_t)atoi(optarg);
      break;
    case 'n':
      nb_tx_desc = (uint16_t)atoi(optarg);
      break;
    case 'b':
      shaped_rate_bps = (uint64_t)atoll(optarg);
      break;
    case 'm': {
      long v = atol(optarg);
      if (v < 1 || v > MAX_PKT_BURST) {
        fprintf(stderr, "-m %s out of range, clamping to [1,%d]\n", optarg,
                MAX_PKT_BURST);
        v = v < 1 ? 1 : MAX_PKT_BURST;
      }
      burst_size = (uint16_t)v;
      break;
    }
    case 'c':
      target_samples = (uint64_t)atoll(optarg);
      break;
    case 'o':
      snprintf(outfile_base, sizeof(outfile_base), "%s", optarg);
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
    case 'T':
      transient_type = (uint32_t)strtoul(optarg, NULL, 10);
      break;
    case 'D':
      period_ms = (uint32_t)strtoul(optarg, NULL, 10);
      break;
    case 'I':
#ifdef CBC
      cbc_poll_us = (uint32_t)strtoul(optarg, NULL, 10);
#else
      fprintf(stderr, "-I is only meaningful for CBC\n");
#endif
      break;
    case 'A':
#ifdef REJ
      rej_add_step = (uint32_t)strtoul(optarg, NULL, 10);
#else
      fprintf(stderr, "-A is only meaningful for REJ\n");
#endif
      break;
    case 'K':
#ifdef REJ
      rej_grow_streak = (uint32_t)strtoul(optarg, NULL, 10);
#else
      fprintf(stderr, "-K is only meaningful for REJ\n");
#endif
      break;
    default:
      fprintf(stderr, "Unknown app option, ignoring.\n");
    }
  }

  if (target_samples == 0)
    rte_exit(EXIT_FAILURE, "-c must be > 0\n");
#ifdef CBC
  if (cbc_poll_us == 0)
    rte_exit(EXIT_FAILURE, "CBC poll interval (-I) must be > 0 us\n");
#endif
#ifdef REJ
  if (rej_add_step == 0)
    rte_exit(EXIT_FAILURE, "REJ add step (-A) must be > 0\n");
  if (rej_grow_streak == 0)
    rte_exit(EXIT_FAILURE, "REJ grow streak (-K) must be > 0\n");
#endif
}

static void print_params(FILE *f, const char *indent, const char *sep) {
  fprintf(f, "%s\"mechanism\": \"%s\"%s", indent, MECHANISM, sep);
#ifdef CBC
  fprintf(f, "%s\"cbc_poll_us\": %u%s", indent, cbc_poll_us, sep);
#endif
#ifdef REJ
  fprintf(f, "%s\"rej_add_step\": %u%s", indent, rej_add_step, sep);
  fprintf(f, "%s\"rej_grow_streak\": %u%s", indent, rej_grow_streak, sep);
  fprintf(f, "%s\"rej_min\": %u%s", indent, REJ_MIN, sep);
#endif
#ifdef PAB
  fprintf(f, "%s\"pab_retry_max\": %u%s", indent, PAB_RETRY_MAX, sep);
#endif
}

static void write_hist_json(FILE *f, const char *name,
                            const uint64_t hist[USED_HIST_MAX], bool last) {
  fprintf(f, "  \"%s\": [\n", name);
  bool first = true;
  for (uint32_t i = 0; i < USED_HIST_MAX; i++) {
    if (hist[i] == 0)
      continue;
    fprintf(f, "%s    {\"value\": %u, \"count\": %" PRIu64 "}",
            first ? "" : ",\n", i, hist[i]);
    first = false;
  }
  fprintf(f, "\n  ]%s\n", last ? "" : ",");
}

static void write_queue_json(uint16_t queue_id, const struct queue_stats *qs,
                             uint64_t recorded_samples, uint64_t offered_pkts,
                             uint64_t attempted_pkts, double gating_pct,
                             double rejection_pct, double tx_pkts_per_second,
                             const uint64_t used_hist[USED_HIST_MAX],
                             const uint64_t watermark_hist[USED_HIST_MAX],
                             uint64_t transient_start, uint64_t transient_end) {
  char fname[300];
  snprintf(fname, sizeof(fname), "%s_q%u.json", outfile_base, queue_id);

  FILE *f = fopen(fname, "w");
  if (f == NULL) {
    fprintf(stderr, "[q%u] Could not open %s for writing\n", queue_id, fname);
    return;
  }

  fprintf(f, "{\n");
  fprintf(f, "  \"queue_id\": %u,\n", queue_id);
  fprintf(f, "  \"nb_tx_desc\": %u,\n", nb_tx_desc);
  fprintf(f, "  \"burst_size\": %u,\n", burst_size);
  fprintf(f, "  \"timer_hz\": %" PRIu64 ",\n", rte_get_tsc_hz());
  fprintf(f, "  \"period_ms\": %u,\n", period_ms);
  fprintf(f, "  \"transient_type\": %u,\n", transient_type);
  fprintf(f, "  \"transient_start\": %" PRIu64 ",\n", transient_start);
  fprintf(f, "  \"transient_end\": %" PRIu64 ",\n", transient_end);
  print_params(f, "  ", ",\n");

  fprintf(f, "  \"samples\": %" PRIu64 ",\n", qs->samples);
  fprintf(f, "  \"recorded_samples\": %" PRIu64 ",\n", recorded_samples);
  fprintf(f, "  \"tx_pkts\": %" PRIu64 ",\n", qs->tx_pkts);
  fprintf(f, "  \"tx_bytes\": %" PRIu64 ",\n", qs->tx_bytes);
  fprintf(f, "  \"app_discarded\": %" PRIu64 ",\n", qs->app_discarded);
  fprintf(f, "  \"occupancy_polls\": %" PRIu64 ",\n", qs->used_polls);
  fprintf(f, "  \"polls_per_sample\": %.6f,\n",
          qs->samples ? (double)qs->used_polls / (double)qs->samples : 0.0);
  fprintf(f, "  \"offered_pkts\": %" PRIu64 ",\n", offered_pkts);
  fprintf(f, "  \"occupancy_gated\": %" PRIu64 ",\n", qs->occupancy_gated);
  fprintf(f, "  \"gating_pct\": %.6f,\n", gating_pct);
  fprintf(f, "  \"attempted_pkts\": %" PRIu64 ",\n", attempted_pkts);
  fprintf(f, "  \"tx_not_accepted\": %" PRIu64 ",\n", qs->tx_not_accepted);
  fprintf(f, "  \"rejection_pct\": %.6f,\n", rejection_pct);
  fprintf(f, "  \"tx_pkts_per_second\": %.2f,\n", tx_pkts_per_second);
  fprintf(f, "  \"reject_events\": %" PRIu64 ",\n", qs->reject_events);

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
          qs->used_polls ? (double)qs->sum_used / (double)qs->used_polls : 0.0);
  fprintf(f, "  \"cycles_count\": %" PRIu64 ",\n", qs->cycles_count);
  fprintf(f, "  \"cycles_tx\": %" PRIu64 ",\n", qs->cycles_tx);
  fprintf(f, "  \"cycles_total\": %" PRIu64 ",\n", qs->cycles_total);
  fprintf(f, "  \"avg_cycles_count\": %.6f,\n",
          qs->used_polls ? (double)qs->cycles_count / (double)qs->used_polls
                         : 0.0);
  fprintf(f, "  \"avg_cycles_tx\": %.6f,\n",
          qs->samples ? (double)qs->cycles_tx / (double)qs->samples : 0.0);
  fprintf(f, "  \"avg_cycles_total\": %.6f,\n",
          qs->samples ? (double)qs->cycles_total / (double)qs->samples : 0.0);

  /* Sparse histograms: [{"value": 32, "count": 100}, ...] */
  write_hist_json(f, "used_histogram", used_hist, false);
  write_hist_json(f, "watermark_histogram", watermark_hist, true);
  fprintf(f, "}\n");

  fclose(f);
}

/*
 * rte_tm shaping: root -> 900 -> 800 -> 700 -> one leaf per Tx queue, with a
 * peak-rate shaper at the root. rate is in BYTES/s (rte_tm convention).
 * Must run before rte_eth_dev_start() on cnxk.
 */
static int tm_shaper_setup(uint16_t pid, uint64_t rate) {
  struct rte_tm_error error;
  struct rte_tm_shaper_params sp;
  struct rte_tm_node_params np;
  int ret;

  memset(&sp, 0, sizeof(sp));
  sp.peak.rate = rate;
  sp.peak.size = 16 * 1024;

  ret = rte_tm_shaper_profile_add(pid, SHAPER_PROFILE_1, &sp, &error);
  if (ret)
    goto fail;

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
  ret = rte_tm_node_add(pid, NODE_800, NODE_900, 0, 1, 2, &np, &error);
  if (ret)
    goto fail;
  ret = rte_tm_node_add(pid, NODE_700, NODE_800, 0, 1, 3, &np, &error);
  if (ret)
    goto fail;

  memset(&np, 0, sizeof(np));
  np.shaper_profile_id = RTE_TM_SHAPER_PROFILE_ID_NONE;
  np.leaf.cman = RTE_TM_CMAN_TAIL_DROP;
  for (int i = 0; i < nb_tx_q; i++) {
    ret = rte_tm_node_add(pid, i, NODE_700, 0, 1, 4, &np, &error);
    if (ret)
      goto fail;
  }

  ret = rte_tm_hierarchy_commit(pid, 1, &error);
  if (ret)
    goto fail;

  printf("rte_tm shaper configured: %" PRIu64 " B/s\n", rate);
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

  /* 1 Rx queue (unused, but some PMDs require one), one Tx queue per
   * worker. */
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

  if (shaped_rate_bps > 0 && tm_shaper_setup(pid, shaped_rate_bps) != 0) {
    fprintf(stderr, "rte_tm shaper setup failed; running without shaping. "
                    "Check rte_tm capabilities of the PMD.\n");
    shaped_rate_bps = 0;
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
}

/* ======================================================================
 * Worker
 * ====================================================================== */

/* B_req for this iteration, given the transient pattern. */
struct load_state {
  uint64_t transient_start;
  uint64_t transient_end;
  uint64_t duty_next; /* next on/off transition, 0 = not started */
  bool duty_on;
};

static inline uint16_t requested_burst(struct load_state *ls, uint64_t now) {
  if (now < ls->transient_start || now >= ls->transient_end)
    return burst_size;

  switch (transient_type) {
  case 0: /* pause: nothing submitted, the Tx queue drains */
    return 0;
  case 1: { /* on/off duty cycle with period_ms on, period_ms off */
    uint64_t half = ms_to_tsc(period_ms);
    if (ls->duty_next == 0) {
      ls->duty_next = now + half;
      ls->duty_on = true;
    } else if (now >= ls->duty_next) {
      ls->duty_on = !ls->duty_on;
      ls->duty_next = now + half;
    }
    return ls->duty_on ? burst_size : 0;
  }
  case 2: /* partial load: smaller bursts */
    return RTE_MIN((uint16_t)TRANSIENT_SMALL_BURST, burst_size);
  default:
    return burst_size;
  }
}

static void print_queue_summary(uint16_t queue_id, const struct queue_stats *qs,
                                uint64_t recorded_samples, double gating_pct,
                                uint64_t attempted_pkts, double rejection_pct,
                                double tx_pkts_per_second,
                                const uint64_t used_hist[USED_HIST_MAX],
                                const uint64_t watermark_hist[USED_HIST_MAX]) {
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
         "period_ms           : %u\n"
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
         queue_id, qs->samples, period_ms, recorded_samples,
         qs->tx_pkts, qs->tx_bytes, qs->app_discarded, qs->used_polls,
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

  if (qs->samples > recorded_samples)
    printf("[q%u] WARNING: raw sample capacity reached: stored %" PRIu64
           " of %" PRIu64 " measurement iterations. Increase -c to keep "
           "the complete time series.\n",
           queue_id, recorded_samples, qs->samples);

  printf("\nTX queue-count histogram:\n");
  for (uint32_t i = 0; i < USED_HIST_MAX; i++)
    if (used_hist[i] != 0)
      printf("queue %u  used=%3u : %" PRIu64 " (%.4f%%)\n", queue_id, i,
             used_hist[i],
             qs->used_polls
                 ? 100.0 * (double)used_hist[i] / (double)qs->used_polls
                 : 0.0);

  printf("\nhigh_wm histogram:\n");
  for (uint32_t i = 0; i < USED_HIST_MAX; i++)
    if (watermark_hist[i] != 0)
      printf("queue %u  watermark=%3u : %" PRIu64 " (%.4f%%)\n", queue_id, i,
             watermark_hist[i],
             qs->used_polls
                 ? 100.0 * (double)watermark_hist[i] / (double)qs->used_polls
                 : 0.0);
}

static void write_samples_bin(const struct worker_ctx *ctx,
                              const struct queue_stats *qs,
                              uint64_t recorded_samples) {
  char fname[300];
  snprintf(fname, sizeof(fname), "%s_q%u.bin", outfile_base, ctx->queue_id);

  FILE *f = fopen(fname, "wb");
  if (f == NULL) {
    fprintf(stderr, "[q%u] Could not open %s for writing\n", ctx->queue_id,
            fname);
    return;
  }

  struct sample_file_header hdr = {
      .magic = SAMPLE_FILE_MAGIC,
      .version = SAMPLE_FILE_VERSION,
      .queue_id = ctx->queue_id,
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
         ctx->queue_id, recorded_samples, fname, sizeof(struct sample_record),
         sizeof(struct queue_stats));
}

static int tx_worker_main(void *arg) {
  struct worker_ctx *ctx = (struct worker_ctx *)arg;
  uint16_t queue_id = ctx->queue_id;
  struct queue_stats *qs = &qstats[queue_id];

  /* Large per-worker arrays live on the heap, not the lcore stack. */
  uint64_t *used_hist = rte_zmalloc("used_hist", USED_HIST_MAX * sizeof(uint64_t), 0);
  uint64_t *watermark_hist =
      rte_zmalloc("wm_hist", USED_HIST_MAX * sizeof(uint64_t), 0);
  struct ctrl *ctrl = rte_zmalloc("ctrl", sizeof(struct ctrl), RTE_CACHE_LINE_SIZE);
  if (used_hist == NULL || watermark_hist == NULL || ctrl == NULL)
    rte_exit(EXIT_FAILURE, "[q%u] cannot allocate worker state\n", queue_id);

  ctrl_init(ctrl);
  qs->first_reject_sample = UINT64_MAX;

  /* Barrier 1: all workers alive before any of them starts traffic. */
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

  /* Warm-up: idle until the common end of the warm-up window. */
  spin_until_tsc(global_warmup_end_tsc);

  /* Barrier 2: all workers warmed up -> common measurement window. */
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

  struct load_state ls = {
      .transient_start = global_start_tsc + ms_to_tsc(TRANSIENT_START_MS),
  };
  ls.transient_end = ls.transient_start + ms_to_tsc(TRANSIENT_LEN_MS);

  spin_until_tsc(global_start_tsc);

  uint64_t recorded_samples = 0;
  uint64_t iter = 0;
  struct rte_mbuf *bufs[MAX_PKT_BURST];

  while (!force_quit) {
    uint64_t now = rte_rdtsc();
    if (now >= global_end_tsc)
      break;

    uint16_t requested = requested_burst(&ls, now);

    if (requested > 0) {
      if (rte_pktmbuf_alloc_bulk(ctx->mbuf_pool, bufs, requested) != 0)
        rte_exit(EXIT_FAILURE, "mbuf allocation failed\n");
      for (uint16_t i = 0; i < requested; i++)
        fill_dummy_packet(bufs[i]);
    }

    struct sample_record *s = recorded_samples < target_samples
                                  ? &ctx->samples[recorded_samples++]
                                  : NULL;

    tx_iteration(ctx, ctrl, s, qs, used_hist, watermark_hist, iter, requested,
                 bufs);
    iter++;
  }

  uint64_t actual_end_tsc = rte_rdtsc();

  uint64_t attempted_pkts = qs->tx_pkts + qs->tx_not_accepted;
  uint64_t offered_pkts = attempted_pkts + qs->occupancy_gated;
  double gating_pct =
      offered_pkts ? 100.0 * (double)qs->occupancy_gated / (double)offered_pkts
                   : 0.0;
  double rejection_pct = attempted_pkts ? 100.0 * (double)qs->tx_not_accepted /
                                              (double)attempted_pkts
                                        : 0.0;
  double measure_seconds =
      (double)(actual_end_tsc - global_start_tsc) / (double)rte_get_tsc_hz();
  double tx_pkts_per_second =
      measure_seconds > 0.0 ? (double)qs->tx_pkts / measure_seconds : 0.0;

  print_queue_summary(queue_id, qs, recorded_samples, gating_pct,
                      attempted_pkts, rejection_pct, tx_pkts_per_second,
                      used_hist, watermark_hist);
  write_queue_json(queue_id, qs, recorded_samples, offered_pkts, attempted_pkts,
                   gating_pct, rejection_pct, tx_pkts_per_second, used_hist,
                   watermark_hist, ls.transient_start, ls.transient_end);
  write_samples_bin(ctx, qs, recorded_samples);

  rte_free(used_hist);
  rte_free(watermark_hist);
  rte_free(ctrl);
  return 0;
}

int main(int argc, char **argv) {
  int ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "EAL init failed\n");
  argc -= ret;
  argv += ret;

  parse_args(argc, argv);
  printf("controller:");
  print_params(stdout, " ", "");
  printf("\n");

  /* ---- Derive the Tx queue count from the worker lcores ---- */
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

  printf("Port %u up. workers=%u nb_tx_q=%u nb_tx_desc=%u burst=%u "
         "shaped_rate=%" PRIu64 " B/s warmup_ms=%" PRIu64
         " measure_ms=%" PRIu64 " raw_capacity=%" PRIu64 "\n",
         port_id, n_workers, nb_tx_q, nb_tx_desc, burst_size, shaped_rate_bps,
         warmup_ms, measure_ms, target_samples);

  /* ---- Allocate per-queue sample buffers and launch workers ---- */
  for (unsigned i = 0; i < n_workers; i++) {
    struct sample_record *samples =
        rte_zmalloc("samples", target_samples * sizeof(struct sample_record),
                    RTE_CACHE_LINE_SIZE);
    if (samples == NULL)
      rte_exit(EXIT_FAILURE, "Cannot allocate sample buffer for queue %u\n",
               i);

    worker_ctx[i].queue_id = (uint16_t)i;
    worker_ctx[i].mbuf_pool = mbuf_pool;
    worker_ctx[i].samples = samples;
  }

  for (unsigned i = 0; i < n_workers; i++) {
    if (worker_lcores[i] == rte_lcore_id()) {
      tx_worker_main(&worker_ctx[i]); /* single-lcore fallback */
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
