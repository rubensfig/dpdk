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
#define SUBPORT_OFFSET	5
#define PIPE_OFFSET	16
#define QUEUE_OFFSET	7
#define COLOR_OFFSET	19
// }

// Switchdev VLAN offload off {
// #define SUBPORT_OFFSET	7
// #define PIPE_OFFSET	18
// #define QUEUE_OFFSET	9
// #define COLOR_OFFSET	19
// }


typedef struct {
    struct rte_mbuf *mbufs[4096];
    uint16_t cnt;
    bool has_pending;
} tc_pending_t;

tc_pending_t pending[N_TC];  // One per traffic class

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

	rte_ether_addr_copy(&eth_hdr->dst_addr, &addr);
	rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
	rte_ether_addr_copy(&addr, &eth_hdr->src_addr);

	return 0;
}

void
app_rx_thread(struct thread_conf **confs)
{
	uint32_t i, nb_rx = 0;
	struct rte_mbuf *rx_mbufs[burst_conf.rx_burst] __rte_cache_aligned;
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
					
				nb_tx = rte_eth_tx_buffer(tx_port, tx_queue, buffer, mbufs[i]);
			}

			// nb_tx = rte_eth_tx_burst(conf->tx_port, 0, mbufs, nb_pkts);
			
			//  if (nb_pkts != nb_tx)
			//  	rte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_pkts - nb_tx);
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

		// nb_pkt = rte_sched_port_dequeue(conf->sched_port, mbufs,
		// 			burst_conf.qos_dequeue, NULL);

		if (likely(nb_pkt > 0))
			while (rte_ring_sp_enqueue_bulk(conf->tx_ring,
					(void **)mbufs, nb_pkt, NULL) == 0)
				; /* empty body */

		conf_idx++;
		if (confs[conf_idx] == NULL)
			conf_idx = 0;
	}
}

#define MAX_BURST 4096
void
app_mixed_thread(struct thread_conf **confs)
{
    struct rte_mbuf *mbufs[burst_conf.ring_burst];

    // struct rte_mbuf *pkts_by_tc[N_TC][burst_conf.qos_dequeue];
    struct rte_mbuf **pkts_by_tc[N_TC];
    struct rte_mbuf **pending_mbufs[N_TC];

    struct thread_conf *conf;
    int conf_idx = 0;

    // int has_pending[N_TC] = {0};
    bool has_pending = false;
    uint32_t pending_cnt = 0;
    uint32_t capacity_pct[N_TC] = {burst_conf.ring_burst};

	for (int i = 0; i < N_TC; i++) {
	    pkts_by_tc[i] = rte_zmalloc("pkts_by_tc",
	        burst_conf.qos_dequeue * sizeof(struct rte_mbuf *),  // Correct size
	        RTE_CACHE_LINE_SIZE);  // Your socket

	    pending_mbufs[i] = rte_zmalloc("pending",
	        burst_conf.qos_dequeue * sizeof(struct rte_mbuf *),  // Correct size
	        RTE_CACHE_LINE_SIZE);  // Your socket
	}


    uint32_t tc_counts[N_TC];

    uint32_t pending_cnt_pq[N_TC];
    for (int i = 0; i < N_TC; i++) {
        pending_cnt_pq[i] = 0;
	capacity_pct[i] = burst_conf.ring_burst;
    }

    struct rte_eth_dev_tx_buffer *buffer;

    while ((conf = confs[conf_idx])) {

        uint32_t nb_pkt_rec = 0;
        uint32_t nb_pkt_deq = 0;
	uint32_t tx_queue = 1;
	int tx_port = conf->tx_port;

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

	/* Dequeue from scheduler regardless of has_pending */
	}
	// nb_pkt_deq = rte_sched_port_dequeue_tc(conf->sched_port, pkts_by_tc, burst_conf.qos_dequeue, capacity_pct, tc_counts);

	nb_pkt_deq = rte_sched_port_dequeue(conf->sched_port, mbufs, burst_conf.qos_dequeue, capacity_pct);
	if (nb_pkt_deq > 0) {
		uint32_t nb_tx;
	    	uint16_t sent = rte_eth_tx_burst(tx_port, 0, &mbufs, nb_pkt_deq);
		if (sent < nb_pkt_deq) {

			uint32_t tx=0;
			uint32_t len=0;

	    		for (uint16_t i = sent; i < nb_pkt_deq; i++) {

				int tc = mbufs[i]->hash.sched.traffic_class;
				len += mbufs[i]->pkt_len;

				if (tc >= N_TX_QUEUES)
				    tc = 1; // fallback to TC1
				tx = rte_eth_tx_buffer(tx_port, tc, tx_buffer[tx_port][tc], mbufs[i]);
				
				if (tx > 0) {
				    pending_cnt_pq[tc] -= tx;
				    if (pending_cnt_pq[tc] < 0)
					pending_cnt_pq[tc] = 0;
				} else if (tx == 0) {
					// buffered, not transmistted
					pending_cnt_pq[tc] += tx;
				    if (pending_cnt_pq[tc] > burst_conf.ring_burst)
					pending_cnt_pq[tc] = burst_conf.ring_burst;
				}
			}
			has_pending = true;
		}
	    }
	for (int i = 0; i < N_TC; i++) {
		int tx = rte_eth_tx_buffer_flush(tx_port, i, tx_buffer[tx_port][i]);

		if (tx > 0) {
		    pending_cnt_pq[i] -= tx;
		    if (pending_cnt_pq[i] < 0)
			pending_cnt_pq[i] = 0;
		}

		capacity_pct[i] = burst_conf.ring_burst - pending_cnt_pq[i];

		if (capacity_pct[i] < 0)
			capacity_pct[i] = 0;
	}
		/*
	    for (int tc = 0; tc < N_TC; tc++) {
		if (tc >= N_TX_QUEUES)
		    tc = 1; // fallback to TC1

		if (tc_counts[tc] == 0)
			continue;

	    	uint16_t sent = rte_eth_tx_burst(tx_port, tc, pkts_by_tc[tc], tc_counts[tc]);
		// printf("tc %d count %d nb pkt deq %d, pkts %x\n", tc, tc_counts[tc], nb_pkt_deq, pkts_by_tc[tc]); // pkts by tc not passed correctly
		// printf("sent %d tc_counts[tc] %d\n", sent, tc_counts[tc]); // pkts by tc not passed correctly

		uint32_t unsent = tc_counts[tc] - sent;
		if (unsent > 0) {
		    rte_memcpy(pending_mbufs[tc],
			       &pkts_by_tc[tc][nb_tx],
			       unsent * sizeof(struct rte_mbuf *));

		    pending_cnt_pq[tc] +=  unsent;
		    tc_counts[tc] -= sent;
		}
	    }
	    	for (uint16_t i = sent; i < tc_counts[tc]; i++) {
			// uint32_t tx = rte_eth_tx_buffer(tx_port, tc, tx_buffer[tx_port][tc], pkts_by_tc[i]);
			//

			// If tx > 0, packets were sent, replenish credits for flushed packets
			if (tx > 0) {
			    pending_cnt_pq[tc] -= tx;
			    if (pending_cnt_pq[tc] < 0)
				pending_cnt_pq[tc] = 0;
			} else if (tx == 0) {
				// buffered, not transmistted
				pending_cnt_pq[tc]++;
			    if (pending_cnt_pq[tc] > burst_conf.ring_burst)
				pending_cnt_pq[tc] = burst_conf.ring_burst;
			}
		} 
	    for (int tc = 0; tc < N_TC; tc++) {
	    	uint16_t sent = rte_eth_tx_burst(tx_port, tc, pending_mbufs[tc], tc_counts[tc]);

		if (sent < pending) {
		    uint16_t remain = pending - sent;
		    memmove(&pending_mbufs[tc][0],
		    	    &pending_mbufs[tc][sent],
		    	    remain * sizeof(struct rte_mbuf *));
		    pending_cnt_pq[tc] = remain;
		} else {
		    pending_cnt_pq[tc] = 0;
		}
	    }
	
	    */

 

    /*
	  for (int q = 0; q < N_TX_QUEUES; q++) {
	  	int tx = rte_eth_tx_buffer_flush(tx_port, q, tx_buffer[tx_port][q]);

		if (tx > 0) {
		    pending_cnt_pq[q] -= tx;
		    if (pending_cnt_pq[q] < 0)
			pending_cnt_pq[q] = 0;
		}

		capacity_pct[q] = burst_conf.ring_burst - pending_cnt_pq[q];
		if (capacity_pct[q] < 0)
			capacity_pct[q] = 0;
	  } */ 

		/* Update statistics */
		APP_STATS_ADD(conf->stat.nb_tx, nb_pkt_deq);
		/* Advance conf pointer */
		conf_idx++;
		if (confs[conf_idx] == NULL)
		    conf_idx = 0;
	}
}


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
}
*/
