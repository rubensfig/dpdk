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
#include <rte_cycles.h>
#include <rte_sched.h>

#include "pending_stats.h"	/* stats_on, stats_tsc() */

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
 *  3: occupancy over time and loop cycles:
 *    tc.pq_area      counter, sum of pq x TSC ticks: (d pq_area) / (d tsc)
 *                    is the time-averaged retry-queue occupancy of a record
 *                    interval
 *    tc.pq_max_win   gauge, peak retry-queue occupancy of the last completed
 *                    window (--stats-win-ms); -1 before the first window
 *    inst.cyc_*      counters, TSC ticks per loop phase (see ctrl_inst_stats)
 *    watch           scheduler queues of the watched pipes (--watch-pipes)
 *    All of it stays 0 / -1 with --no-stats.
 */
#define CTRL_STATS_VERSION 3
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
	/* ---- occupancy over time (version 3) ---- */
	uint64_t pq_area;	/* counter: sum of pq x TSC ticks */
	int64_t pq_max_win;	/* gauge: peak pq of the last completed window */
	/* writer-private (not exported) */
	uint32_t pq_max_cur;	/* peak pq of the current window */
};

/*
 * Loop cycles (version 3). Every loop iteration is split into four phases,
 * TSC ticks per phase:
 *   cyc_enq   RX ring dequeue + rte_sched_port_enqueue
 *   cyc_ctrl  controller budget (incl. CBC polls / QBC queue reads) and the
 *             retry transmits of all TCs
 *   cyc_deq   rte_sched_port_dequeue_tc
 *   cyc_tx    fresh transmits, retry-queue refill and controller update
 * and the whole iteration goes to cyc_busy if it moved a packet (enqueued,
 * retried or dequeued one), else to cyc_idle. Cycles per delivered packet =
 * (d cyc_busy) / (d sum tc.sent).
 */
struct ctrl_inst_stats {
	uint64_t loops;		/* worker loop iterations */
	uint64_t sched_enq;	/* packets offered to rte_sched_port_enqueue */
	uint64_t sched_drop;	/* of those, dropped by HQoS */
	uint64_t sched_deq;	/* packets dequeued from HQoS */
	uint64_t cyc_busy;	/* iterations that moved a packet */
	uint64_t cyc_idle;	/* the others */
	uint64_t cyc_enq;
	uint64_t cyc_ctrl;
	uint64_t cyc_deq;
	uint64_t cyc_tx;
};

/*
 * Watched pipes (version 3, --watch-pipes): the scheduler queues of up to
 * CS_WATCH_MAX pipes of subport 0 per instance, TCs 0 .. CS_WATCH_TCS-1,
 * read by the worker every watch period (--watch-us) with
 * rte_sched_queue_read_stats(). That call clears the queue counters, so do
 * not query /qos/pipe_stats for the same pipes at the same time.
 *   qlen_area     counter, sum of qlen x TSC ticks (qlen held between reads)
 *   pkts, dropped counters, packets written to / dropped by the queue
 *   qlen          gauge, queue length at the last read
 *   qlen_max_win  gauge, peak qlen of the last completed window
 * Mean queueing delay of a record interval (Little's law):
 *   (d qlen_area / d tsc) / (d pkts / d tsc) = d qlen_area / d pkts  [ticks]
 */
#define CS_WATCH_MAX 8
#define CS_WATCH_TCS 4

struct ctrl_watch_stats {
	uint64_t qlen_area[CS_WATCH_TCS];
	uint64_t pkts[CS_WATCH_TCS];
	uint64_t dropped[CS_WATCH_TCS];
	int64_t qlen[CS_WATCH_TCS];
	int64_t qlen_max_win[CS_WATCH_TCS];
	uint32_t qlen_max_cur[CS_WATCH_TCS];	/* writer-private */
};

struct ctrl_stats {
	struct ctrl_inst_stats inst;
	struct ctrl_tc_stats tc[CS_N_TC];
	/* watched pipes: configuration (set before the run) and state */
	uint32_t n_watch;
	uint32_t watch_pipe[CS_WATCH_MAX];
	struct ctrl_watch_stats watch[CS_WATCH_MAX];
	/* writer-private clocks of ctrl_stats_tick() */
	uint64_t last_tsc;	/* previous tick */
	uint64_t win_end;	/* end of the current peak window */
	uint64_t watch_last;	/* previous watched-pipe read */
	/* written by the RX lcore: keep it on its own cache line */
	alignas(RTE_CACHE_LINE_SIZE) uint64_t rx_ring_drop;
};

/* --stats-win-ms, --watch-us (args.c) */
extern uint32_t stats_win_ms;
extern uint32_t watch_us;

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
		t->pq_max_win = CS_UNSET;
		t->pq_max_cur = 0;
	}
	for (uint32_t i = 0; i < CS_WATCH_MAX; i++)
		for (int q = 0; q < CS_WATCH_TCS; q++) {
			cs->watch[i].qlen[q] = CS_UNSET;
			cs->watch[i].qlen_max_win[q] = CS_UNSET;
			cs->watch[i].qlen_max_cur[q] = 0;
		}
	cs->last_tsc = 0;
	cs->win_end = 0;
	cs->watch_last = 0;
}

/*
 * Once per loop iteration of the flow, before its TX path: integrates the
 * retry-queue occupancy over time, closes the peak window and reads the
 * watched pipes when their period is due. now is the TSC at the start of the
 * iteration; port the flow's scheduler. No-op with --no-stats.
 */
static inline void
ctrl_stats_tick(struct ctrl_stats *cs, struct rte_sched_port *port, uint64_t now)
{
	if (unlikely(!stats_on))
		return;

	const uint64_t hz = rte_get_tsc_hz();

	if (unlikely(cs->last_tsc == 0)) {	/* first tick */
		cs->last_tsc = now;
		cs->win_end = now + hz / 1000 * stats_win_ms;
		cs->watch_last = now;
		return;
	}

	uint64_t dt = now - cs->last_tsc;

	cs->last_tsc = now;
	for (int tc = 0; tc < CS_N_TC; tc++) {
		struct ctrl_tc_stats *t = &cs->tc[tc];

		if (t->pq > 0)
			t->pq_area += (uint64_t)t->pq * dt;
	}

	bool close_win = now >= cs->win_end;

	if (close_win) {
		for (int tc = 0; tc < CS_N_TC; tc++) {
			struct ctrl_tc_stats *t = &cs->tc[tc];

			t->pq_max_win = t->pq_max_cur;
			t->pq_max_cur = (uint32_t)t->pq;
		}
		cs->win_end += hz / 1000 * stats_win_ms;
		if (cs->win_end <= now)		/* fell behind: restart the window */
			cs->win_end = now + hz / 1000 * stats_win_ms;
	}

	if (cs->n_watch == 0)
		return;
	uint64_t wdt = now - cs->watch_last;

	if (wdt < hz / 1000000 * watch_us && !close_win)
		return;
	cs->watch_last = now;
	for (uint32_t i = 0; i < cs->n_watch; i++) {
		struct ctrl_watch_stats *w = &cs->watch[i];

		for (int q = 0; q < CS_WATCH_TCS; q++) {
			struct rte_sched_queue_stats st;
			uint16_t qlen = 0;

			/* held value since the previous read */
			if (w->qlen[q] > 0)
				w->qlen_area[q] += (uint64_t)w->qlen[q] * wdt;
			if (rte_sched_queue_read_stats(port,
					cs->watch_pipe[i] * RTE_SCHED_QUEUES_PER_PIPE + q,
					&st, &qlen) != 0)
				continue;
			w->pkts[q] += st.n_pkts;
			w->dropped[q] += st.n_pkts_dropped;
			w->qlen[q] = qlen;
			if (qlen > w->qlen_max_cur[q])
				w->qlen_max_cur[q] = qlen;
			if (close_win) {
				w->qlen_max_win[q] = w->qlen_max_cur[q];
				w->qlen_max_cur[q] = qlen;
			}
		}
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

	if (unlikely(!stats_on))
		return;
	t->pq = pq;
	if (pq > t->pq_max_cur)
		t->pq_max_cur = pq;
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
