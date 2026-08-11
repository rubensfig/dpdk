#pragma once
#include <stdint.h>
#include <string.h>
#include <rte_cycles.h>
#include <math.h>

#define PENDING_MAX 512

/* ── Histogram bucket config ─────────────────────────── */
#define PHIST_OCC_BUCKETS   16   /* occupancy:  bucket i → [i*(PENDING_MAX/16), ...) */
#define PHIST_RETRY_BUCKETS  8   /* retry count: 0,1,2,3,4,5,6,7+                    */

#define PHIST_BUCKETS_PER_DECADE 30      /* resolution knob: higher = finer */
#define PHIST_MIN_DECADE_EXP     2       /* smallest decade: 10^2 ns = 100ns */
#define PHIST_MAX_DECADE_EXP     10      /* largest decade:  10^10 ns = 10s  */
#define PHIST_NUM_DECADES        (PHIST_MAX_DECADE_EXP - PHIST_MIN_DECADE_EXP + 1)
#define PHIST_LAT_BUCKETS        (PHIST_NUM_DECADES * PHIST_BUCKETS_PER_DECADE + 1)

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

/* Precomputed once at startup: log10(10^PHIST_MIN_DECADE_EXP) baseline */
static inline uint32_t pstats_lat_bucket_index(uint64_t ns) {
	if (ns < 1) ns = 1;  /* guard log10(0) */
	
	/* Clamp anything below the smallest decade into bucket 0 */
	double decade_min = (double)PHIST_MIN_DECADE_EXP;
	double log_ns = log10((double)ns);
	
	if (log_ns < decade_min) return 0;
	
	double offset_decades = log_ns - decade_min;       /* e.g. 2.37 decades in */
	uint64_t idx = (uint64_t)(offset_decades * PHIST_BUCKETS_PER_DECADE);
	
	if (idx >= (uint64_t)(PHIST_NUM_DECADES * PHIST_BUCKETS_PER_DECADE))
	return PHIST_LAT_BUCKETS - 1;  /* overflow bucket */
	
	return (uint32_t)idx;
}

/* Inverse: lower edge (in ns) represented by a given bucket index.
 *    Useful for printing/plotting bucket boundaries. */
static inline double pstats_lat_bucket_lower_ns(uint32_t idx) {
	if (idx >= (uint32_t)(PHIST_NUM_DECADES * PHIST_BUCKETS_PER_DECADE))
		return (double)1e0 * pow(10.0, PHIST_MAX_DECADE_EXP); /* overflow floor */
	double offset_decades = (double)idx / PHIST_BUCKETS_PER_DECADE;
	return pow(10.0, PHIST_MIN_DECADE_EXP + offset_decades);
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

static inline void
pstats_record_loss(pending_tc_stats_t *s, uint32_t loss)
{
	s->retry_loss += loss;

}

#define PSTATS_DEBUG_LAT 1
static inline void pstats_record_latency(pending_tc_stats_t *s, uint64_t enqueue_tsc) {
	uint64_t dt_tsc = rte_rdtsc() - enqueue_tsc;
	uint64_t hz     = rte_get_tsc_hz();
	uint64_t us     = dt_tsc / (hz / 1000000ULL);
	uint64_t ns     = us * 1000ULL;
	
	s->lat_sum_tsc += dt_tsc;
	s->lat_samples++;
	if (dt_tsc > s->lat_max_tsc) s->lat_max_tsc = dt_tsc;
	
	uint32_t b = pstats_lat_bucket_index(ns);
	s->lat_hist[b]++;
}

static inline void
pstats_record_retry(pending_tc_stats_t *s, uint16_t retry_count)
{
	uint32_t b = retry_count < PHIST_RETRY_BUCKETS ? retry_count : PHIST_RETRY_BUCKETS - 1;
	s->retry_hist[b]++;

	if (retry_count > 0) s->retry_total++;
}
