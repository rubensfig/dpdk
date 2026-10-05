/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdint.h>

#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_memcpy.h>
#include <rte_byteorder.h>
#include <rte_branch_prediction.h>
#include <rte_sched.h>

#include "main.h"
#include "pending_stats.h"

/*
 * QoS parameters are encoded as follows:
 *		Outer VLAN ID defines subport
 *		Inner VLAN ID defines pipe
 *		Destination IP host (0.0.0.XXX) defines queue
 * Values below define offset to each field from start of frame
 */
// VLAN offload ON {
#define SUBPORT_OFFSET	7
#define PIPE_OFFSET	18
#define QUEUE_OFFSET	9
#define COLOR_OFFSET	19
// }

// Switchdev VLAN offload off {
// #define SUBPORT_OFFSET	7
// #define PIPE_OFFSET	18
// #define QUEUE_OFFSET	9
// #define COLOR_OFFSET	19
// }

struct pending_q {
	struct rte_mbuf *pkts[PENDING_MAX];
	uint64_t         enqueue_tsc[PENDING_MAX]; /* parallel TSC stamp array    */
	uint8_t          retry_cnt[PENDING_MAX];   /* how many tx attempts so far */
	uint16_t         head, tail, cnt, cnt_pktsize;
} __rte_cache_aligned;

static inline void
pending_init(struct pending_q *q)
{
	    q->head = q->tail = q->cnt = 0;
}

static inline void pending_enqueue_burst(struct pending_q *q, struct rte_mbuf **mbufs, uint16_t nb_mbufs) {
	for (uint16_t i = 0; i < nb_mbufs; i++) {
		if (unlikely(q->cnt == PENDING_MAX)) {
			/* policy decision: drop remaining packets */
			rte_pktmbuf_free(mbufs[i]);
			continue;
		}

		q->pkts[q->tail] = mbufs[i];
		q->tail = (q->tail + 1) & (PENDING_MAX - 1);
		q->cnt++;
		q->cnt_pktsize += mbufs[i]->pkt_len;
	}
}

static inline void pending_enqueue_burst_tracked(struct pending_q *q, pending_tc_stats_t *s, struct rte_mbuf **mbufs, uint16_t nb_mbufs) {
	uint64_t now = rte_rdtsc();
	uint16_t dropped = 0;

	for (uint16_t i = 0; i < nb_mbufs; i++) {

		if (unlikely(q->cnt >= PENDING_MAX)) {
			printf("DROPPED\n");
			/* policy decision: drop remaining packets */
			rte_pktmbuf_free(mbufs[i]);
			s->retry_loss++;
			continue;
		}

		q->pkts[q->tail] = mbufs[i];
		q->enqueue_tsc[q->tail]  = now;
		q->retry_cnt[q->tail] = 1;
		q->tail = (q->tail + 1) & (PENDING_MAX - 1);
		q->cnt++;
		q->cnt_pktsize += mbufs[i]->pkt_len;
	}

}

/*
static inline void
pending_enqueue_burst_tracked(struct pending_q *q, pending_tc_stats_t *s,
		                               struct rte_mbuf **pkts_in, uint16_t n)
{
	uint64_t now = rte_rdtsc();
	uint16_t dropped = 0;

	for (uint16_t i = 0; i < n; i++) {
		if (q->cnt >= PENDING_MAX) {
		       	rte_pktmbuf_free(pkts_in[i]);
		       	dropped++; 
			continue; 
		}

		uint16_t slot         = (q->tail + i) % PENDING_MAX;
		q->pkts[slot]         = pkts_in[i];
		q->enqueue_tsc[slot]  = now;
		q->retry_cnt[slot]    = 1;
		q->tail               = (q->tail + 1) % PENDING_MAX;
		q->cnt++;
	}

	s->retry_loss += dropped;
}
*/

/* Call after a successful pending_consume() to record latency + retries */
static inline void
pending_consume_tracked(struct pending_q *q, pending_tc_stats_t *s, uint16_t n)
{
    for (uint16_t i = 0; i < n; i++) {
	struct rte_mbuf *m = q->pkts[(q->head + i) & (PENDING_MAX - 1)];

	pstats_record_latency(s, q->enqueue_tsc[(q->head + i) & (PENDING_MAX - 1)]);
	pstats_record_retry(s, q->retry_cnt[(q->head + i) & (PENDING_MAX - 1)]);
	s->pkts_retry_total += q->retry_cnt[(q->head + i) & (PENDING_MAX - 1)];

	q->cnt_pktsize -= m->pkt_len;
    }

    q->head = (q->head + n) & (PENDING_MAX - 1);
    q->cnt -= n;
}

static inline void
pending_enqueue(struct pending_q *q, struct rte_mbuf *m)
{
    if (unlikely(q->cnt == PENDING_MAX)) {
	/* policy decision: drop */
	rte_pktmbuf_free(m);
	return;
     }

     q->pkts[q->tail] = m;
     q->tail = (q->tail + 1) & (PENDING_MAX - 1);
     q->cnt++;
     q->cnt_pktsize += m->pkt_len;
}

static inline uint16_t
pending_peek(struct pending_q *q, struct rte_mbuf **out, uint16_t max)
{
    uint16_t n = RTE_MIN(q->cnt, max);

	for (uint16_t i = 0; i < n; i++) {
		out[i] = q->pkts[(q->head + i) & (PENDING_MAX - 1)];
	}
    return n;
}

static inline void
pending_consume(struct pending_q *q, uint16_t n)
{
    for (uint16_t i = 0; i < n; i++) {
	struct rte_mbuf *m = q->pkts[(q->head + i) & (PENDING_MAX - 1)];
	q->cnt_pktsize -= m->pkt_len;
    }

    q->head = (q->head + n) & (PENDING_MAX - 1);
    q->cnt -= n;
}


static inline int get_pkt_sched(struct rte_mbuf *m, uint32_t *subport, uint32_t *pipe,
			uint32_t *traffic_class, uint32_t *queue, uint32_t *color)
{
	uint16_t *pdata = rte_pktmbuf_mtod(m, uint16_t *);
	struct rte_ether_hdr *eth_hdr;
	struct rte_ether_addr addr;
	uint16_t pipe_queue;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

 	/* Outer VLAN ID*/
	*subport = ((m->vlan_tci & 0xE000) >> 13) & (port_params.n_subports_per_port -1);

 	/* Dst Addr */
 	*pipe = (rte_be_to_cpu_16(pdata[PIPE_OFFSET]) & 0xFFFF);

	pipe_queue = ((rte_be_to_cpu_16(pdata[QUEUE_OFFSET]) & 0x00FC) >> 2);

 	/* Traffic class (TOS) */
 	*traffic_class = pipe_queue > RTE_SCHED_TRAFFIC_CLASS_BE ?
 			RTE_SCHED_TRAFFIC_CLASS_BE : pipe_queue;

 	/* Traffic class queue (TOS) */
 	*queue = pipe_queue - *traffic_class;

	// for (int i = 0; i < 20; i++)
	// 	printf("%x\n", rte_be_to_cpu_16(pdata[QUEUE_OFFSET]));
	// printf("tos=0x%x dscp=%u tc=%u q=%u\n",
	// 		       rte_be_to_cpu_16(pdata[QUEUE_OFFSET]) & 0xff,
	// 		              pipe_queue,
	// 			             *traffic_class,
	// 				            *queue);
	// printf("\n\n");
 	/* Color */
 	*color = 0;

	// rte_ether_addr_copy(&eth_hdr->dst_addr, &addr);
	// rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
	// rte_ether_addr_copy(&addr, &eth_hdr->src_addr);
	//        uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
	//
	/*
	uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
	if (ether_type == RTE_ETHER_TYPE_IPV4) {
	     struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

	    if (ip_hdr->next_proto_id == IPPROTO_UDP) {
			rte_ether_addr_copy(&eth_hdr->dst_addr, &addr);
			rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
			rte_ether_addr_copy(&addr, &eth_hdr->src_addr);
	    }
	}
	*/

	return 0;
}

void
app_rx_thread(struct thread_conf **confs)
{
	uint32_t i, nb_rx;
	alignas(RTE_CACHE_LINE_SIZE) struct rte_mbuf *rx_mbufs[burst_conf.rx_burst];
	struct thread_conf *conf;
	int conf_idx = 0;

	uint32_t subport;
	uint32_t pipe;
	uint32_t traffic_class;
	uint32_t queue;
	uint32_t color;

	while ((conf = confs[conf_idx])) {
		nb_rx = rte_eth_rx_burst(conf->rx_port, conf->rx_queue, rx_mbufs,
				burst_conf.rx_burst);

		if (likely(nb_rx != 0)) {
			APP_STATS_ADD(conf->stat.nb_rx, nb_rx);

			for(i = 0; i < nb_rx; i++) {
				get_pkt_sched(rx_mbufs[i],
						&subport, &pipe, &traffic_class, &queue, &color);
				rte_sched_port_pkt_write(conf->sched_port,
						rx_mbufs[i],
						subport, pipe,
						traffic_class, queue,
						(enum rte_color) color);
			}

			if (unlikely(rte_ring_sp_enqueue_bulk(conf->rx_ring,
					(void **)rx_mbufs, nb_rx, NULL) == 0)) {
				for(i = 0; i < nb_rx; i++) {
					rte_pktmbuf_free(rx_mbufs[i]);

					APP_STATS_ADD(conf->stat.nb_drop, 1);
				} 
			}
		}
		conf_idx++;
		if (confs[conf_idx] == NULL)
			conf_idx = 0;
	}
}

void
app_tx_thread(struct thread_conf **confs)
{
	struct rte_mbuf *mbufs[burst_conf.qos_dequeue];
	struct thread_conf *conf;
	int conf_idx = 0;
	int nb_pkts;
	struct rte_eth_dev_tx_buffer *buffer;

	while ((conf = confs[conf_idx])) {
		nb_pkts = rte_ring_sc_dequeue_burst(conf->tx_ring, (void **)mbufs,
					burst_conf.qos_dequeue, NULL);
		uint16_t nb_tx = 0;
		if (likely(nb_pkts != 0)) {
			for(int i = 0; i < nb_pkts; i++) {
				int tx_queue = mbufs[i]->hash.sched.traffic_class;
				int tx_port = conf->tx_port;

				if (tx_queue > N_TX_QUEUES) {
					tx_queue = 1;
				}

				buffer = tx_buffer[tx_port][tx_queue];

				nb_tx += rte_eth_tx_buffer(tx_port, tx_queue, buffer, mbufs[i]);
			}
			APP_STATS_ADD(conf->stat.nb_tx, nb_tx);

			// nb_tx = rte_eth_tx_burst(conf->tx_port, 0, mbufs, nb_pkts);

			// if (nb_pkts != nb_tx)
				// rte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_pkts - nb_tx);
		}

		conf_idx++;
		if (confs[conf_idx] == NULL)
			conf_idx = 0;
	}
}


void
app_worker_thread(struct thread_conf **confs)
{
	struct rte_mbuf *mbufs[burst_conf.ring_burst];
	struct thread_conf *conf;
	int conf_idx = 0;

	while ((conf = confs[conf_idx])) {
		uint32_t nb_pkt;

		/* Read packet from the ring */
		nb_pkt = rte_ring_sc_dequeue_burst(conf->rx_ring, (void **)mbufs,
					burst_conf.ring_burst, NULL);
		if (likely(nb_pkt)) {
			int nb_sent = rte_sched_port_enqueue(conf->sched_port, mbufs,
					nb_pkt);

			APP_STATS_ADD(conf->stat.nb_drop, nb_pkt - nb_sent);
			APP_STATS_ADD(conf->stat.nb_rx, nb_pkt);
		}

		nb_pkt = rte_sched_port_dequeue(conf->sched_port, mbufs,
					burst_conf.qos_dequeue);

		if (likely(nb_pkt > 0))
			while (rte_ring_sp_enqueue_bulk(conf->tx_ring,
					(void **)mbufs, nb_pkt, NULL) == 0)
				; /* empty body */

		conf_idx++;
		if (confs[conf_idx] == NULL)
			conf_idx = 0;
	}
}

#if MIXED_THREAD_PERTCDEQUEUE
void
app_mixed_thread(struct thread_conf **confs)
{
    struct rte_mbuf *mbufs[burst_conf.ring_burst];
    struct thread_conf *conf;
    int conf_idx = 0;

    uint32_t tc_ov[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    struct pending_q pending[N_TC];
    for (int i = 0; i < N_TC; i++)
	pending_init(&pending[i]);

    struct rte_mbuf *tc_mbufs[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE][burst_conf.qos_dequeue];
    struct rte_mbuf **pkts[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
    uint32_t tc_counts[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    /* Initialize pkts array programatically */
    for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
	        pkts[tc] = tc_mbufs[tc];
		tc_ov[tc] = 4096;
    }

    while ((conf = confs[conf_idx])) {
	uint32_t nb_pkt_rec = 0;

	/* RX → Scheduler enqueue */
	nb_pkt_rec = rte_ring_sc_dequeue_burst(conf->rx_ring, (void **)mbufs, burst_conf.ring_burst, NULL);

	if (likely(nb_pkt_rec)) {
		uint32_t nb_sent = rte_sched_port_enqueue(conf->sched_port, mbufs, nb_pkt_rec);
		APP_STATS_ADD(conf->stat.nb_drop, nb_pkt_rec - nb_sent);
		APP_STATS_ADD(conf->stat.nb_rx,  nb_pkt_rec);
	}

	/* TX path - send pending packets first */
	for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		tc_counts[tc] = 0;
	}

	/* Dequeue from scheduler and send new packets */
	rte_sched_port_dequeue_tc(conf->sched_port, pkts, burst_conf.qos_dequeue, NULL, tc_counts);

	for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {

		if (tc_counts[tc] == 0)
			continue;

		uint16_t sent = rte_eth_tx_burst(conf->tx_port, tc, pkts[tc], tc_counts[tc]);

		APP_STATS_ADD(conf->stat.nb_tx, sent);
	}

	conf_idx++;
	if (confs[conf_idx] == NULL)
	conf_idx = 0;
     }
}
#endif
#if MIXED_THREAD_PRIOBP
void
app_mixed_thread(struct thread_conf **confs)
{
    struct rte_mbuf *mbufs[burst_conf.ring_burst];
    struct thread_conf *conf;
    int conf_idx = 0;

    uint32_t tc_ov[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    struct pending_q pending[N_TC];
    for (int i = 0; i < N_TC; i++)
	pending_init(&pending[i]);

    struct rte_mbuf *tc_mbufs[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE][burst_conf.qos_dequeue];
    struct rte_mbuf **pkts[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
    uint32_t tc_counts[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    /* Initialize pkts array programatically */
    for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
	        pkts[tc] = tc_mbufs[tc];
		tc_ov[tc] = burst_conf.qos_dequeue;
    }

    while ((conf = confs[conf_idx])) {
	uint32_t nb_pkt_rec = 0;

	/* RX → Scheduler enqueue */
	nb_pkt_rec = rte_ring_sc_dequeue_burst(conf->rx_ring, (void **)mbufs, burst_conf.ring_burst, NULL);

	if (likely(nb_pkt_rec)) {
		uint32_t nb_sent = rte_sched_port_enqueue(conf->sched_port, mbufs, nb_pkt_rec);
		APP_STATS_ADD(conf->stat.nb_drop, nb_pkt_rec - nb_sent);
		APP_STATS_ADD(conf->stat.nb_rx,  nb_pkt_rec);
	}

	/* TX path - send pending packets first */
	for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		tc_counts[tc] = 0;
		uint16_t n = pending_peek(&pending[tc], mbufs, burst_conf.qos_dequeue);
		if (n > 0) {
				uint16_t sent = rte_eth_tx_burst(conf->tx_port, tc, mbufs, n);
				if (sent) {
					pending_consume(&pending[tc], sent);
					APP_STATS_ADD(conf->stat.nb_tx, sent);
				}
			}
			uint16_t space = PENDING_MAX - pending[tc].cnt;
			tc_ov[tc] = RTE_MIN(space, burst_conf.qos_dequeue);
		}

	/* Dequeue from scheduler and send new packets */
	rte_sched_port_dequeue_tc(conf->sched_port, pkts, burst_conf.qos_dequeue, tc_ov, tc_counts);

	for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		if (tc_counts[tc] == 0)
			continue;

		// printf("tc_counts[%d] %d\n", tc, tc_counts[tc]);
		uint16_t sent = rte_eth_tx_burst(conf->tx_port, tc, pkts[tc], tc_counts[tc]);

		if (unlikely(sent < tc_counts[tc])) {
			pending_enqueue_burst( &pending[tc], &pkts[tc][sent], tc_counts[tc] - sent);
		}
		// printf("sent %d tc counts [%d] %d cap [%d] %d tc ov [%d] %d\n", sent, tc, tc_counts[tc], tc, pending[tc].cnt, tc, tc_ov[tc]);

		APP_STATS_ADD(conf->stat.nb_tx, sent);
	}

	conf_idx++;
	if (confs[conf_idx] == NULL)
	conf_idx = 0;
     }
}
#endif

#if MIXED_THREAD_QBC || MIXED_THREAD_CBC
/*
 * Capacity controllers from the paper, one instance per TxQ (= traffic
 * class). Each loop iteration: compute the per-TC budget B_cap, let the
 * scheduler dequeue at most B_cap packets of that TC (tc_ov), transmit them,
 * and update the controller with B_sent. Packets the NIC rejects are dropped
 * (counted in nb_drop and in the per-TC "loss" column).
 */
static inline void
capacity_rx_to_sched(struct thread_conf *conf, struct rte_mbuf **mbufs)
{
	uint32_t nb_pkt_rec = rte_ring_sc_dequeue_burst(conf->rx_ring,
			(void **)mbufs, burst_conf.ring_burst, NULL);

	if (likely(nb_pkt_rec)) {
		uint32_t nb_sent = rte_sched_port_enqueue(conf->sched_port, mbufs,
				nb_pkt_rec);
		APP_STATS_ADD(conf->stat.nb_drop, nb_pkt_rec - nb_sent);
		APP_STATS_ADD(conf->stat.nb_rx, nb_pkt_rec);
	}
}

/* Transmit one TC's dequeued burst; returns B_sent. */
static inline uint16_t
capacity_tx(struct thread_conf *conf, pending_tc_stats_t *s, int tc,
		struct rte_mbuf **pkts, uint32_t b_tx)
{
	uint64_t t0 = rte_rdtsc();
	uint16_t sent = rte_eth_tx_burst(conf->tx_port, tc, pkts, b_tx);
	s->cycles_tx += rte_rdtsc() - t0;
	s->pkts_tx_total += sent;

	if (unlikely(sent < b_tx)) {
		rte_pktmbuf_free_bulk(&pkts[sent], b_tx - sent);
		s->retry_loss += b_tx - sent;
		APP_STATS_ADD(conf->stat.nb_drop, b_tx - sent);
	}
	APP_STATS_ADD(conf->stat.nb_tx, sent);
	return sent;
}
#endif

#if MIXED_THREAD_QBC
/*
 * QBC: Queue Occupancy-Based Capacity (paper Algorithm 2).
 *
 *   U = rte_eth_tx_queue_count(); Delta = gcd of the non-zero changes of U
 *   B_cap = B_req        while H is undefined
 *         = 0            if U >= H
 *         = H - U        otherwise (every burst is capped at the boundary)
 *   partial transmit (once Delta > 0): H = min(H, U)
 *   full transmit:                     H = max(H, U + B_sent)
 *
 * Since bursts are capped at H - U, H rises only before the first rejection
 * and is non-increasing afterwards. Delta only delays the first update of H
 * until the queue state has been seen to move.
 *
 * B_req is the per-TC dequeue limit qos_dequeue. If the PMD has no queue
 * count (e.g. iavf), the TC runs without backpressure and a warning is
 * printed once.
 */
struct qbc_state {
	uint32_t h;		/* H: congestion boundary */
	uint32_t u_prev;	/* U_prev */
	uint32_t delta;		/* Delta: queue-state granularity */
	uint32_t u;		/* U of the current iteration */
	bool h_valid;		/* H defined */
	bool have_prev;
	bool have_u;
};

static inline uint32_t
qbc_gcd(uint32_t a, uint32_t b)
{
	while (b) {
		uint32_t t = a % b;
		a = b;
		b = t;
	}
	return a;
}

/* i) Observe queue state, ii) compute the transmission budget. */
static inline uint32_t
qbc_budget(struct qbc_state *q, uint16_t port, int tc, uint32_t b_req,
		bool *warned)
{
	int count = rte_eth_tx_queue_count(port, tc);

	if (unlikely(count < 0)) {
		if (!*warned) {
			printf("QBC: rte_eth_tx_queue_count(port %u, txq %d) failed "
			       "(%d): running without backpressure\n",
			       port, tc, count);
			*warned = true;
		}
		q->have_u = false;
		return b_req;
	}

	uint32_t u = (uint32_t)count;
	if (q->have_prev && u != q->u_prev)
		q->delta = qbc_gcd(q->delta,
				u > q->u_prev ? u - q->u_prev : q->u_prev - u);
	q->u_prev = u;
	q->have_prev = true;
	q->u = u;
	q->have_u = true;

	if (!q->h_valid)
		return b_req;
	if (u >= q->h)
		return 0;
	return RTE_MIN(q->h - u, b_req);
}

/* iv) Update the congestion boundary. */
static inline void
qbc_update(struct qbc_state *q, uint32_t b_tx, uint32_t b_sent)
{
	if (!q->have_u || b_tx == 0)
		return;

	if (b_sent < b_tx) {
		if (q->delta == 0)	/* queue state not yet seen to move */
			return;
		q->h = q->h_valid ? RTE_MIN(q->h, q->u) : q->u;
	} else {
		uint32_t v = q->u + b_sent;
		q->h = q->h_valid ? RTE_MAX(q->h, v) : v;
	}
	q->h_valid = true;
}

void app_mixed_thread(struct thread_conf **confs)
{
	struct rte_mbuf *mbufs[burst_conf.ring_burst];
	struct thread_conf *conf;
	int conf_idx = 0;

	struct flow_conf *flow = container_of(confs[0], struct flow_conf, wt_thread);
	pending_tc_stats_t *stats = flow->tc_stats;

	struct qbc_state qbc[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	bool warned = false;

	struct rte_mbuf *tc_mbufs[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE][burst_conf.qos_dequeue];
	struct rte_mbuf **pkts[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t tc_counts[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t tc_ov[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];

	memset(qbc, 0, sizeof(qbc));
	for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		pstats_reset(&stats[tc]);
		pkts[tc] = tc_mbufs[tc];
	}

	while ((conf = confs[conf_idx])) {
		capacity_rx_to_sched(conf, mbufs);

		for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++)
			tc_ov[tc] = qbc_budget(&qbc[tc], conf->tx_port, tc,
					burst_conf.qos_dequeue, &warned);

		memset(tc_counts, 0, sizeof(tc_counts));
		rte_sched_port_dequeue_tc(conf->sched_port, pkts,
				burst_conf.qos_dequeue, tc_ov, tc_counts);

		for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
			if (tc_counts[tc] == 0)
				continue;
			uint16_t sent = capacity_tx(conf, &stats[tc], tc, pkts[tc],
					tc_counts[tc]);
			qbc_update(&qbc[tc], tc_counts[tc], sent);
		}

		conf_idx++;
		if (confs[conf_idx] == NULL)
			conf_idx = 0;
	}
}
#endif /* MIXED_THREAD_QBC */

#if MIXED_THREAD_CBC
/*
 * CBC: Completion-Based Capacity (paper Algorithm 1).
 *
 *   every T_poll: C += rte_eth_tx_done_cleanup()
 *   B_cap = max(0, N_desc - (Q - C)),  Q += B_sent
 *
 * N_desc is the configured TxQ depth (ring_conf.tx_size). T_poll is
 * CBC_POLL_US (compile time). A TxQ with nothing outstanding is not polled.
 */
#ifndef CBC_POLL_US
#define CBC_POLL_US 10u
#endif

struct cbc_state {
	uint64_t q;		/* Q: packets accepted by the NIC */
	uint64_t c;		/* C: completed packets */
	uint64_t last_poll_tsc;
};

void app_mixed_thread(struct thread_conf **confs)
{
	struct rte_mbuf *mbufs[burst_conf.ring_burst];
	struct thread_conf *conf;
	int conf_idx = 0;

	struct flow_conf *flow = container_of(confs[0], struct flow_conf, wt_thread);
	pending_tc_stats_t *stats = flow->tc_stats;

	struct cbc_state cbc[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	const uint64_t poll_tsc = (rte_get_tsc_hz() * CBC_POLL_US) / 1000000ULL;
	const uint64_t n_desc = ring_conf.tx_size;
	bool warned = false;

	struct rte_mbuf *tc_mbufs[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE][burst_conf.qos_dequeue];
	struct rte_mbuf **pkts[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t tc_counts[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t tc_ov[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];

	memset(cbc, 0, sizeof(cbc));
	for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		pstats_reset(&stats[tc]);
		pkts[tc] = tc_mbufs[tc];
	}

	printf("CBC: N_desc=%" PRIu64 " T_poll=%u us\n", n_desc, CBC_POLL_US);

	while ((conf = confs[conf_idx])) {
		capacity_rx_to_sched(conf, mbufs);

		uint64_t now = rte_rdtsc();
		for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
			struct cbc_state *c = &cbc[tc];

			/* i) Process transmission completions every T_poll */
			if (c->q != c->c && now - c->last_poll_tsc >= poll_tsc) {
				int freed = rte_eth_tx_done_cleanup(conf->tx_port, tc, 0);

				if (freed > 0) {
					c->c = RTE_MIN(c->c + (uint64_t)freed, c->q);
				} else if (unlikely(freed < 0 && !warned)) {
					printf("CBC: rte_eth_tx_done_cleanup(port %u, txq %d) "
					       "failed (%d): no completions, CBC will stall\n",
					       conf->tx_port, tc, freed);
					warned = true;
				}
				c->last_poll_tsc = now;
			}

			/* ii) Compute transmission budget */
			uint64_t u = c->q - c->c;
			uint64_t b_cap = u < n_desc ? n_desc - u : 0;
			tc_ov[tc] = (uint32_t)RTE_MIN(b_cap, (uint64_t)burst_conf.qos_dequeue);
		}

		memset(tc_counts, 0, sizeof(tc_counts));
		rte_sched_port_dequeue_tc(conf->sched_port, pkts,
				burst_conf.qos_dequeue, tc_ov, tc_counts);

		/* iii) Transmit, iv) update accepted work */
		for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
			if (tc_counts[tc] == 0)
				continue;
			cbc[tc].q += capacity_tx(conf, &stats[tc], tc, pkts[tc],
					tc_counts[tc]);
		}

		conf_idx++;
		if (confs[conf_idx] == NULL)
			conf_idx = 0;
	}
}
#endif /* MIXED_THREAD_CBC */

#if MIXED_THREAD_PRIOBP_STATS
void
app_mixed_thread(struct thread_conf **confs)
{
    struct rte_mbuf *mbufs[burst_conf.ring_burst];
    struct thread_conf *conf;
    int conf_idx = 0;

    uint32_t tc_ov[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    struct pending_q pending[N_TC];
    for (int i = 0; i < N_TC; i++)
	pending_init(&pending[i]);

    struct flow_conf *flow = container_of(confs[0], struct flow_conf, wt_thread);
    pending_tc_stats_t *stats = flow->tc_stats;

    for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++)
	        pstats_reset(&stats[tc]);

    struct rte_mbuf *tc_mbufs[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE][burst_conf.qos_dequeue];
    struct rte_mbuf **pkts[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
    uint32_t tc_counts[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    /* Initialize pkts array programatically */
    for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
	        pkts[tc] = tc_mbufs[tc];
		tc_ov[tc] = burst_conf.qos_dequeue;
    }

    while ((conf = confs[conf_idx])) {
	uint32_t nb_pkt_rec = 0;

	/* RX → Scheduler enqueue */
	nb_pkt_rec = rte_ring_sc_dequeue_burst(conf->rx_ring, (void **)mbufs, burst_conf.ring_burst, NULL);

	if (likely(nb_pkt_rec)) {
		uint32_t nb_sent = rte_sched_port_enqueue(conf->sched_port, mbufs, nb_pkt_rec);
		APP_STATS_ADD(conf->stat.nb_drop, nb_pkt_rec - nb_sent);
		APP_STATS_ADD(conf->stat.nb_rx,  nb_pkt_rec);
	}

	/* ── TX path: drain pending ──────────────────────────── */
	for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		tc_counts[tc] = 0;
		uint16_t n = pending_peek(&pending[tc], mbufs, burst_conf.qos_dequeue);

		if (n > 0) {
			uint64_t t0 = rte_rdtsc();
			uint16_t sent = rte_eth_tx_burst(conf->tx_port, tc, mbufs, n);
			uint64_t t1 = rte_rdtsc();
			if (sent) {
				pending_consume_tracked(&pending[tc], &stats[tc], sent);
				//pending_consume(&pending[tc], sent);
				APP_STATS_ADD(conf->stat.nb_tx, sent);
				stats[tc].cycles_retry += (t1 - t0);
				stats[tc].pkts_tx_total += sent;
			}

		}

		/* STATS: occupancy snapshot */
		pstats_record_occupancy(&stats[tc], pending[tc].cnt);

		uint16_t used = pending[tc].cnt;
		uint16_t headroom = (used < PENDING_MAX) ? (PENDING_MAX - used) : 0;
		tc_ov[tc] = RTE_MIN(headroom, burst_conf.qos_dequeue);
	}


	/* ── Scheduler dequeue + fresh TX ───────────────────── */
	rte_sched_port_dequeue_tc(conf->sched_port, pkts, burst_conf.qos_dequeue, tc_ov, tc_counts);

	for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		if (tc_counts[tc] == 0) continue;

		uint64_t t0   = rte_rdtsc();
		uint16_t sent = rte_eth_tx_burst(conf->tx_port, tc, pkts[tc], tc_counts[tc]);
		uint64_t t1   = rte_rdtsc();

		stats[tc].cycles_tx     += (t1 - t0);
		stats[tc].pkts_tx_total += sent;

		if (unlikely(sent < tc_counts[tc])) {
			pending_enqueue_burst_tracked(&pending[tc], &stats[tc], &pkts[tc][sent], tc_counts[tc] - sent);
			// pending_enqueue_burst(&pending[tc], &pkts[tc][sent], tc_counts[tc] - sent);
		}
		APP_STATS_ADD(conf->stat.nb_tx, sent);
	}

	conf_idx++;
	if (confs[conf_idx] == NULL)
	conf_idx = 0;
     }
}
#endif

#if MIXED_THREAD_AGGBP
void
app_mixed_thread(struct thread_conf **confs)
{
    struct rte_mbuf *mbufs[burst_conf.ring_burst];
    struct rte_mbuf *pending_mbufs[burst_conf.ring_burst];

    struct thread_conf *conf;
    int conf_idx = 0;

    // int has_pending[N_TC] = {0};
    bool has_pending = false;

    struct pending_q pending;
    // for (int i = 0; i < N_TC; i++)
	pending_init(&pending);

    while ((conf = confs[conf_idx])) {

        uint32_t nb_pkt_rec = 0;
        uint32_t nb_pkt_deq = 0;

        /* ============================================================
         * RX → Scheduler enqueue
         * ============================================================ */
        nb_pkt_rec = rte_ring_sc_dequeue_burst(conf->rx_ring,
                                               (void **)mbufs,
                                               burst_conf.ring_burst,
                                               NULL);

        if (likely(nb_pkt_rec)) {
            uint32_t nb_sent = rte_sched_port_enqueue(conf->sched_port,
                                                      mbufs, nb_pkt_rec);

            APP_STATS_ADD(conf->stat.nb_drop, nb_pkt_rec - nb_sent);
            APP_STATS_ADD(conf->stat.nb_rx,  nb_pkt_rec);
        }

        /* ============================================================
         * TX path
         * ============================================================ */
	if (pending.cnt) {
		uint16_t n = pending_peek(&pending, mbufs, burst_conf.qos_dequeue);
		
		uint16_t sent  = rte_eth_tx_burst(conf->tx_port, 0, mbufs, n);
		
		if (sent) {
			pending_consume(&pending, sent);
			APP_STATS_ADD(conf->stat.nb_tx, sent);
		}
		// printf("Pending cnt: %d, sent %d\n",  pending.cnt, sent);
	}
		
	/* ============================================================
	*      * TX path – dequeue new only if no pending
	* ============================================================ */
	if (pending.cnt == 0) {
		
		nb_pkt_deq = rte_sched_port_dequeue(conf->sched_port, mbufs, burst_conf.qos_dequeue);
		
		uint16_t sent = 0;
		if (nb_pkt_deq) {
			sent = rte_eth_tx_burst(conf->tx_port, 0, mbufs, nb_pkt_deq);
			
			if (sent < nb_pkt_deq) {
				for (uint16_t i = sent; i < nb_pkt_deq; i++)
					pending_enqueue(&pending, mbufs[i]);
			}
		
		APP_STATS_ADD(conf->stat.nb_tx, sent);
		}
		// printf("TX burst: tried %u, sent %u\n", nb_pkt_deq, sent);
	}



        /* Advance conf pointer */
        conf_idx++;
        if (confs[conf_idx] == NULL)
            conf_idx = 0;
    }
}
#endif
#if MIXED_THREAD_PRIOPROP
void
app_mixed_thread(struct thread_conf **confs)
{
    struct rte_mbuf *mbufs[burst_conf.ring_burst];
    struct rte_mbuf *pending_mbufs[burst_conf.ring_burst];

    struct thread_conf *conf;
    int conf_idx = 0;

   struct rte_eth_dev_tx_buffer *buffer;

    while ((conf = confs[conf_idx])) {
	uint16_t nb_pkts = rte_ring_sc_dequeue_burst(conf->rx_ring, (void **)mbufs, burst_conf.ring_burst, NULL);
	if (likely(nb_pkts)) {
		int nb_sent = rte_sched_port_enqueue(conf->sched_port, mbufs, nb_pkts);

		APP_STATS_ADD(conf->stat.nb_drop, nb_pkts - nb_sent);
		APP_STATS_ADD(conf->stat.nb_rx, nb_pkts);
	}

	nb_pkts = rte_sched_port_dequeue(conf->sched_port, mbufs, burst_conf.qos_dequeue);

	if (likely(nb_pkts)) {
		for(int i = 0; i < nb_pkts; i++) {
			int tx_queue = mbufs[i]->hash.sched.traffic_class;
			int tx_port = conf->tx_port;
	
			if (tx_queue > N_TX_QUEUES) {
				tx_queue = 1;	
			}
	
			buffer = tx_buffer[tx_port][tx_queue];
				
			rte_eth_tx_buffer(tx_port, tx_queue, buffer, mbufs[i]);
		}
	}

	conf_idx++;
	if (confs[conf_idx] == NULL)
		conf_idx = 0;
    }
}
#endif
/*
void
app_mixed_thread(struct thread_conf **confs)
{
	struct rte_mbuf *mbufs[burst_conf.ring_burst];
	struct thread_conf *conf;
	int conf_idx = 0;

	while ((conf = confs[conf_idx])) {
		uint32_t nb_pkt;

		nb_pkt = rte_ring_sc_dequeue_burst(conf->rx_ring, (void **)mbufs,
					burst_conf.ring_burst, NULL);
		if (likely(nb_pkt)) {
			int nb_sent = rte_sched_port_enqueue(conf->sched_port, mbufs,
					nb_pkt);

			APP_STATS_ADD(conf->stat.nb_drop, nb_pkt - nb_sent);
			APP_STATS_ADD(conf->stat.nb_rx, nb_pkt);
		}


		nb_pkt = rte_sched_port_dequeue(conf->sched_port, mbufs,
					burst_conf.qos_dequeue);
		if (likely(nb_pkt > 0)) {
			uint16_t nb_tx = rte_eth_tx_burst(conf->tx_port, 0, mbufs, nb_pkt);
			if (nb_tx != nb_pkt)
				rte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_pkt - nb_tx);
		}

		conf_idx++;
		if (confs[conf_idx] == NULL)
			conf_idx = 0;
	}
} */
