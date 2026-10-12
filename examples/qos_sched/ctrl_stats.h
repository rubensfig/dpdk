/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef _CTRL_STATS_H_
#define _CTRL_STATS_H_

/*
 * Run telemetry for the transmit controllers (none, pab, qbc, cbc, rej).
 *
 * Written only by the worker lcore of a flow (and, for rx_ring_drop, by its
 * RX lcore), read by the telemetry thread through /qos/ctrl_stats. Counters
 * are monotonic for the whole run and are never reset (unlike
 * pending_tc_stats_t, which app_stat() clears every second), so a reader
 * gets rates by differencing two records over their tsc. Gauges hold the
 * last value; -1 means "not defined" (e.g. H before QBC has learned it).
 *
 * Aligned 64-bit loads and stores are atomic on x86-64 and arm64, so the
 * reader needs no lock; a record may mix values from two loop iterations,
 * which is irrelevant at a 100 ms sampling interval.
 */

#include <stdalign.h>
#include <stdint.h>
#include <rte_common.h>
#include <rte_sched.h>

#define CS_N_TC RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE

/*
 * Version of the counter semantics, reported in /qos/scenario.
 *  1 (field absent): ov was read back after rte_sched_port_dequeue_tc(),
 *    which decrements the budget array, so ov held the budget LEFT OVER
 *    (offered - dequeued), and `bound` was computed from it. In the PAB
 *    loop the same left-over value was also passed as B_cap, so PAB's
 *    cap and stalls were wrong too.
 *  2: ov, bound (and PAB's cap, stalls) use the budget as offered,
 *    copied before the dequeue call.
 */
#define CTRL_STATS_VERSION 2
#define CS_UNSET (-1)

struct ctrl_tc_stats {
	/* ---- counters, all mechanisms ---- */
	uint64_t active;	/* decisions with B_tx > 0 */
	uint64_t req;		/* sum B_req */
	uint64_t cap;		/* sum B_cap (controller budget) */
	uint64_t ov;		/* sum fresh budget offered to the scheduler */
	uint64_t deq;		/* sum fresh packets dequeued from HQoS */
	uint64_t tx;		/* sum B_tx = retried + fresh */
	uint64_t sent;		/* sum B_sent (accepted by the NIC) */
	uint64_t retried;	/* sum packets offered from the retry queue */
	uint64_t retry_sent;	/* sum of those accepted */
	uint64_t dropped;	/* freed after leaving HQoS (NIC reject w/o retry, PQ full) */
	uint64_t stalls;	/* decisions with B_cap == 0 */
	uint64_t bound;		/* decisions where the fresh budget was used up and < B_req */
	/* ---- counters, per mechanism ---- */
	uint64_t polls;		/* CBC: completion polls */
	uint64_t freed;		/* CBC: completions returned by the polls */
	uint64_t fb_cyc;	/* CBC: TSC cycles spent in the polls */
	uint64_t h_lowered;	/* QBC: decreases of H */
	uint64_t cuts;		/* REJ: window cuts after a partial transmit */
	/* ---- gauges ---- */
	int64_t pq;		/* retry queue occupancy */
	int64_t q_minus_c;	/* CBC: Q - C, outstanding packets */
	int64_t u;		/* QBC: U' = U - U0 */
	int64_t u0;		/* QBC: empty-queue reading */
	int64_t h;		/* QBC: congestion boundary H */
	int64_t delta;		/* QBC: signal step */
	int64_t w;		/* REJ: window W */
};

struct ctrl_inst_stats {
	uint64_t loops;		/* worker loop iterations */
	uint64_t sched_enq;	/* packets offered to rte_sched_port_enqueue */
	uint64_t sched_drop;	/* of those, dropped by HQoS */
	uint64_t sched_deq;	/* packets dequeued from HQoS */
};

struct ctrl_stats {
	struct ctrl_inst_stats inst;
	struct ctrl_tc_stats tc[CS_N_TC];
	/* written by the RX lcore: keep it on its own cache line */
	alignas(RTE_CACHE_LINE_SIZE) uint64_t rx_ring_drop;
};

static inline void
ctrl_stats_init_gauges(struct ctrl_stats *cs)
{
	for (int tc = 0; tc < CS_N_TC; tc++) {
		struct ctrl_tc_stats *t = &cs->tc[tc];

		t->pq = 0;
		t->q_minus_c = CS_UNSET;
		t->u = CS_UNSET;
		t->u0 = CS_UNSET;
		t->h = CS_UNSET;
		t->delta = CS_UNSET;
		t->w = CS_UNSET;
	}
}

/*
 * Common per-decision accounting. b_cap is the controller budget, ov the
 * fresh budget handed to the scheduler, deq what it dequeued, r_tried and
 * r_sent the retry burst, sent the total accepted packets.
 *
 * Idle iterations (nothing retried or dequeued although the scheduler was
 * allowed to dequeue) are skipped, so req/cap/active count decisions in
 * which a TC had work or was blocked, not loop spins.
 */
static inline void
ctrl_stats_decision(struct ctrl_tc_stats *t, uint32_t b_req, uint32_t b_cap,
		uint32_t ov, uint32_t deq, uint32_t r_tried, uint32_t r_sent,
		uint32_t sent, uint32_t dropped, uint32_t pq)
{
	uint32_t b_tx = r_tried + deq;

	t->pq = pq;
	/* idle: nothing to send and nothing withheld; not a decision */
	if (b_tx == 0 && ov != 0)
		return;

	t->req += b_req;
	t->cap += b_cap;
	t->ov += ov;
	t->deq += deq;
	t->tx += b_tx;
	t->sent += sent;
	t->retried += r_tried;
	t->retry_sent += r_sent;
	t->dropped += dropped;
	t->active += b_tx > 0;
	t->stalls += b_cap == 0;
	t->bound += (ov < b_req) && (deq == ov);
}

#endif /* _CTRL_STATS_H_ */
