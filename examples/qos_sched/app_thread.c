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

/*
 * QoS parameters are encoded as follows:
 *		Outer VLAN ID defines subport
 *		Inner VLAN ID defines pipe
 *		Destination IP host (0.0.0.XXX) defines queue
 * Values below define offset to each field from start of frame
 */
// VLAN offload ON {
// #define SUBPORT_OFFSET	5
// #define PIPE_OFFSET	16
// #define QUEUE_OFFSET	7
// #define COLOR_OFFSET	19
// }

// Switchdev VLAN offload off {
#define SUBPORT_OFFSET	7
#define PIPE_OFFSET	18
#define QUEUE_OFFSET	9
#define COLOR_OFFSET	19
// }

#define PENDING_MAX 4096   /* tune: must cover worst-case backpressure */

struct pending_q {
	struct rte_mbuf *pkts[PENDING_MAX];
	uint16_t head;   /* dequeue */
	uint16_t tail;   /* enqueue */
	uint16_t cnt;
	uint16_t cnt_pktsize;
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

	pipe_queue = (rte_be_to_cpu_16(pdata[QUEUE_OFFSET]) & 0x00FF);

 	/* Traffic class (TOS) */
 	*traffic_class = pipe_queue > RTE_SCHED_TRAFFIC_CLASS_BE ?
 			RTE_SCHED_TRAFFIC_CLASS_BE : pipe_queue;

 	/* Traffic class queue (TOS) */
 	*queue = pipe_queue - *traffic_class;
 	
 	/* Color */
 	*color = 0;

	// rte_ether_addr_copy(&eth_hdr->dst_addr, &addr);
	// rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
	// rte_ether_addr_copy(&addr, &eth_hdr->src_addr);

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
