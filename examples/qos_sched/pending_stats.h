#pragma once
#include <stdint.h>
#include <string.h>
#include <rte_cycles.h>

#define PENDING_MAX 4096

/* ── Histogram bucket config ─────────────────────────── */
#define PHIST_OCC_BUCKETS   16   /* occupancy:  bucket i → [i*(PENDING_MAX/16), ...) */
#define PHIST_LAT_BUCKETS   16   /* latency ns: 0,64,128,256,512,1k,2k,4k,...        */
#define PHIST_RETRY_BUCKETS  8   /* retry count: 0,1,2,3,4,5,6,7+                    */

typedef struct {
	/* ── Queue dynamics ─────────────────────────── */
	uint64_t occ_sum;                        /* Σ occupancy samples                  */
	uint64_t occ_samples;                    /* number of samples taken              */
	uint32_t occ_max;                        /* peak occupancy ever seen             */
	uint64_t occ_hist[PHIST_OCC_BUCKETS];    /* histogram of occupancy snapshots     */
	
	int64_t  prev_occ;                       /* for growth-rate tracking             */
	int64_t  growth_sum;                     /* Σ |delta| between samples            */
	uint64_t growth_samples;
	
	/* ── Retry behavior ─────────────────────────── */
	uint64_t retry_hist[PHIST_RETRY_BUCKETS];/* hist of #retries before tx success   */
	uint64_t retry_loss;                     /* pkts dropped because queue was full  */
	uint64_t retry_total;                    /* total pkts that ever needed a retry  */
	
	/* ── Latency (TSC-based, converted on read) ─ */
	uint64_t lat_sum_tsc;                    /* Σ residence time in TSC ticks        */
	uint64_t lat_max_tsc;                    /* worst-case residence time            */
	uint64_t lat_samples;
	uint64_t pkts_tx_total;
	uint64_t pkts_retry_total;
	uint64_t lat_hist[PHIST_LAT_BUCKETS];    /* bucket edges in ns (power-of-2)      */

	uint64_t cycles_tx;                      /* TSC cycles spent in tx burst (total) */
	uint64_t cycles_retry;                   /* TSC cycles spent draining pending    */
} pending_tc_stats_t;

static const uint64_t lat_hist_edges_ns[PHIST_LAT_BUCKETS] = {
	10000,      /*  10µs */
	50000,      /*  50µs */
	100000,     /* 100µs */
	250000,     /* 250µs */
	500000,     /* 500µs */
	1000000,    /*   1ms */
	5000000,    /*   5ms */
	10000000,   /*  10ms */
	50000000,   /*  50ms */
	100000000,  /* 100ms */
	250000000,  /* 250ms */
	500000000,  /* 500ms */
	1000000000, /*    1s */
	2000000000, /*    2s */
	5000000000, /*    5s */
	UINT64_MAX
};

static inline void pstats_reset(pending_tc_stats_t *s) {
memset(s, 0, sizeof(*s));
s->prev_occ = -1;
}

/* ── Helpers called from hot path ────────────────────── */

static inline void
pstats_record_occupancy(pending_tc_stats_t *s, uint32_t occ)
{
s->occ_sum += occ;
s->occ_samples++;

if (occ > s->occ_max) 
	s->occ_max = occ;

/* occupancy histogram: linear buckets of size PENDING_MAX/BUCKETS */
uint32_t b = (occ * PHIST_OCC_BUCKETS) / (PENDING_MAX + 1);
if (b >= PHIST_OCC_BUCKETS) 
	b = PHIST_OCC_BUCKETS - 1;

s->occ_hist[b]++;

/* growth rate */
if (s->prev_occ >= 0) {
	int64_t delta = (int64_t)occ - s->prev_occ;
	s->growth_sum += delta >= 0 ? delta : -delta;
	s->growth_samples++;
}
s->prev_occ = (int64_t)occ;
}

#define PSTATS_DEBUG_LAT 1
static inline void
pstats_record_latency(pending_tc_stats_t *s, uint64_t enqueue_tsc)
{
	uint64_t dt_tsc = rte_rdtsc() - enqueue_tsc;
	uint64_t hz     = rte_get_tsc_hz();
	uint64_t us     = dt_tsc / (hz / 1000000ULL);
	uint64_t ns     = us * 1000ULL;
	
	#ifdef PSTATS_DEBUG_LAT
	static uint64_t dbg_count = 0;
	if (dbg_count++ < 5)
	printf("[lat_dbg] dt_tsc=%lu hz=%lu us=%lu ns=%lu\n",
	dt_tsc, hz, us, ns);
	#endif
	
	s->lat_sum_tsc += dt_tsc;
	s->lat_samples++;
	if (dt_tsc > s->lat_max_tsc) s->lat_max_tsc = dt_tsc;
	
	for (int b = 0; b < PHIST_LAT_BUCKETS; b++) {
	if (ns < lat_hist_edges_ns[b]) { s->lat_hist[b]++; return; }
	}
	s->lat_hist[PHIST_LAT_BUCKETS - 1]++;
}

static inline void
pstats_record_retry(pending_tc_stats_t *s, uint16_t retry_count)
{
	uint32_t b = retry_count < PHIST_RETRY_BUCKETS ? retry_count : PHIST_RETRY_BUCKETS - 1;
	s->retry_hist[b]++;

	if (retry_count > 0) s->retry_total++;
}
