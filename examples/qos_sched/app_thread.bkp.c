/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Modified for Load-Aware Backpressure Control
 */

#include <stdint.h>
#include <time.h>
#include <string.h>

#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_memcpy.h>
#include <rte_byteorder.h>
#include <rte_branch_prediction.h>
#include <rte_sched.h>
#include <rte_ring.h>

#include "main.h"

/* Backpressure configuration */
#define HIGH_WATER_MARK 60      /* Queue occupancy threshold (%) */
#define LOW_WATER_MARK 20       /* Queue occupancy for recovery (%) */
#define CAPACITY_REDUCTION_STEP 10  /* Reduce by 10% per step */
#define MIN_CAPACITY 50         /* Minimum capacity: 30% */

/* VLAN offsets */
#define SUBPORT_OFFSET	5
#define PIPE_OFFSET	12
#define QUEUE_OFFSET	7
#define COLOR_OFFSET	19


/* Global array of port statistics */
static uint32_t num_ports = 0;

/**
 * update_backpressure_state()
 * 
 * Monitor thread load and manage backpressure capacity.
 * Calculates load from packets processed between enqueue/dequeue.
 * Updates subport_capacity for rte_sched dequeue control.
 * 
 * Parameters:
 *   tx_port: Output port to control
 * 
 * Returns: void
 * 
 * Thread load calculation:
 *   load = packets_dequeued / packets_enqueued
 *   if load > 0.8: entering overload
 *   if load < 0.3: exiting overload (recovery)
 */

static inline void
update_backpressure_state(uint32_t tx_port)
{
	port_statistics_t *port_stats = &port_statistics[tx_port];
	thread_load_stats_t *load = &port_stats->load_stats;
	// port_backpressure_state_t *bp = &port_stats->backpressure;
	
	uint64_t current_time = rte_get_timer_cycles();
	uint64_t hz = rte_get_timer_hz();
	uint64_t time_delta_us =
	((current_time - load->last_update_time) * 1000000) / hz;
	
	if (time_delta_us < BP_CHECK_INTERVAL_US)
		return;
	
	/* ---------------------------------------------------------- */
	/*    TRUE PER-TC LOAD CALCULATION                            */
	/*    load_tc = bytes_out[tc] / packets_in                    */
	/* ---------------------------------------------------------- */
	for (int tc = 0; tc < N_TC; tc++) {
		double load_tc = 0.0;
		
		if (load->packets_in[tc] > 0)
			load_tc = (double)load->packets_out[tc] / (double)load->packets_in[tc];

		// load->load_tc[tc] = load_tc;
		
		/* CURRENT TC STATE */
		port_backpressure_state_t *bp = &port_stats->backpressure[tc];
		uint8_t state = bp->state;
		uint8_t lvl   = bp->reduction_level;
		uint32_t cap  = bp->capacity_pct;
		
		/* -------------------------------------------------- */
		/*          PER-TC STATE MACHINE                     */
		/* -------------------------------------------------- */
		
		/* ------------------ OVERLOAD --------------------- */
		if (load_tc > 0.8) {
			if (state == 0) {
				bp->state = 1;
				bp->last_state_change = current_time;
				
				RTE_LOG(INFO, APP, "Port %u TC %d: OVERLOAD (load=%.2f)\n", tx_port, tc, load_tc);
			}
			
			if (lvl < 7) {
				lvl++;
				bp->reduction_level = lvl;
				
				cap = 100 - (lvl * CAPACITY_REDUCTION_STEP);
				if (cap < MIN_CAPACITY) 
					cap = MIN_CAPACITY;
					
				bp->capacity_pct = cap;
				
				RTE_LOG(INFO, APP, "Port %u TC %d: Reduce capacity to %u%% (level=%u)\n", tx_port, tc, cap, lvl);
			}
		}
		
		/* ------------------ RECOVERY ---------------------- */
		else if (load_tc < 0.3) {
			if (state == 1) {
				bp->state = 0;
				bp->last_state_change = current_time;
				
				RTE_LOG(INFO, APP, "Port %u TC %d: NORMAL (load=%.2f)\n", tx_port, tc, load_tc);
			}
			
			if (lvl > 0) {
				lvl--;
				bp->reduction_level = lvl;
				
				cap = 100 - (lvl * CAPACITY_REDUCTION_STEP);

				if (cap > 100)
					cap = 100;
				
				bp->capacity_pct = cap;
				
				RTE_LOG(INFO, APP, "Port %u TC %d: Recover capacity to %u%% (level=%u)\n", tx_port, tc, cap, lvl);
			}
		}
		
		/* Output: set per-TC scheduler capacity */
		port_stats->subport_capacity[tc] = bp->capacity_pct;

	/* ---------------------------------------------------------- */
	/* Reset stats for next interval                             */
	/* ---------------------------------------------------------- */
	load->packets_in[tc] = 0;
	load->packets_out[tc] = 0;
	load->bytes_out[tc] = 0;
	}
	
	load->last_update_time = current_time;
}



static inline int
get_pkt_sched(struct rte_mbuf *m, uint32_t *subport, uint32_t *pipe,
			uint32_t *traffic_class, uint32_t *queue, uint32_t *color)
{
	uint16_t *pdata = rte_pktmbuf_mtod(m, uint16_t *);
	struct rte_ether_hdr *eth_hdr;
	struct rte_ether_addr addr;
	uint16_t pipe_queue;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* Outer VLAN ID */
	*subport = ((m->vlan_tci & 0xE000) >> 13) & 
		(port_params.n_subports_per_port - 1);

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
	uint32_t i, nb_rx;
	struct rte_mbuf *rx_mbufs[burst_conf.rx_burst] __rte_cache_aligned;
	struct thread_conf *conf;
	int conf_idx = 0;

	uint32_t subport;
	uint32_t pipe;
	uint32_t traffic_class;
	uint32_t queue;
	uint32_t color;

	while ((conf = confs[conf_idx])) {
		nb_rx = rte_eth_rx_burst(conf->rx_port, conf->rx_queue, rx_mbufs, burst_conf.rx_burst);

		if (likely(nb_rx != 0)) {
			APP_STATS_ADD(conf->stat.nb_rx, nb_rx);

			for (i = 0; i < nb_rx; i++) {
				get_pkt_sched(rx_mbufs[i], &subport, &pipe, &traffic_class, &queue, &color);
				
				rte_sched_port_pkt_write(conf->sched_port,
					rx_mbufs[i],
					subport, pipe,
					traffic_class, queue,
					(enum rte_color) color);

				if (unlikely(rte_ring_sp_enqueue(conf->rx_ring, (void *)rx_mbufs[i]))) {
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

/*
void
app_tx_thread(struct thread_conf **confs)
{
	struct rte_mbuf *mbufs[burst_conf.qos_dequeue];
	struct thread_conf *conf;
	int conf_idx = 0;
	int nb_pkts;
	
	while ((conf = confs[conf_idx])) {
		nb_pkts = rte_ring_sc_dequeue_burst(conf->tx_ring, (void **)mbufs, burst_conf.qos_dequeue, NULL);

		if (likely(nb_pkts != 0)) {
			uint16_t nb_tx = rte_eth_tx_burst(conf->tx_port, 0, mbufs, nb_pkts);
			if (nb_pkts != nb_tx)
			rte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_pkts - nb_tx);
		}
		
		conf_idx++;
		if (confs[conf_idx] == NULL)
			conf_idx = 0;
	}
}
*/


void
app_tx_thread(struct thread_conf **confs)
{
	struct rte_mbuf *mbufs[burst_conf.qos_dequeue];
	struct thread_conf *conf;
	int conf_idx = 0;
	int nb_pkts;
	struct rte_eth_dev_tx_buffer *buffer;

	while ((conf = confs[conf_idx])) {
		/*
		uint32_t tx_port = conf->tx_port;
		nb_pkts = rte_ring_sc_dequeue_burst(conf->tx_ring, (void **)mbufs, burst_conf.qos_dequeue, NULL);

		if (likely(nb_pkts > 0)) {
			
			for (int i = 0; i < nb_pkts; i++) {
				
				int tx_queue = mbufs[i]->hash.sched.traffic_class;
				if (tx_queue != 0)
					tx_queue = 1;

				port_statistics[tx_port].load_stats.packets_out[tx_queue] += nb_pkts;
				port_statistics[tx_port].load_stats.bytes_out[tx_queue] += mbufs[i]->pkt_len;

				buffer = tx_buffer[tx_port][tx_queue];
				
				rte_eth_tx_buffer(tx_port, tx_queue, buffer, mbufs[i]);
			}
		}
		
		*/
		conf_idx++;
		if (confs[conf_idx] == NULL)
			conf_idx = 0;
	}
}

void
app_mixed_thread(struct thread_conf **confs)
{
    struct rte_mbuf *mbufs[burst_conf.ring_burst];
    struct rte_mbuf *pending_mbufs[burst_conf.ring_burst];

    struct thread_conf *conf;
    int conf_idx = 0;

    bool has_pending = false;
    uint32_t pending_cnt = 0;

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

        if (!has_pending) {

            /* Only dequeue when no pending packets */
            nb_pkt_deq = rte_sched_port_dequeue(conf->sched_port,
                                                mbufs,
                                                burst_conf.qos_dequeue, NULL);

            if (nb_pkt_deq > 0) {

                uint16_t nb_tx = rte_eth_tx_burst(conf->tx_port, 0,
                                                  mbufs, nb_pkt_deq);

                if (nb_tx < nb_pkt_deq) {
                    /* Store unsent mbuf pointers using rte_memcpy */
                    pending_cnt = nb_pkt_deq - nb_tx;
                    rte_memcpy(pending_mbufs,
                               &mbufs[nb_tx],
                               pending_cnt * sizeof(struct rte_mbuf *));
                    // has_pending = false;
                    has_pending = true;
                }

                APP_STATS_ADD(conf->stat.nb_tx, nb_tx);
            }

        } else {

            /* Retry sending pending packets */
            uint16_t nb_tx = rte_eth_tx_burst(conf->tx_port, 0,
                                              pending_mbufs,
                                              pending_cnt);

            if (nb_tx < pending_cnt) {
                /* Move remaining pointers down (cheap) */
                pending_cnt -= nb_tx;
                rte_memcpy(pending_mbufs,
                        &pending_mbufs[nb_tx],
                        pending_cnt * sizeof(struct rte_mbuf *));
            } else {
                /* Pending backlog has cleared */
                has_pending = false;
                pending_cnt = 0;
            }

            APP_STATS_ADD(conf->stat.nb_tx, nb_tx);
        }

        /* Advance conf pointer */
        conf_idx++;
        if (confs[conf_idx] == NULL)
            conf_idx = 0;
    }
}
// broken
void
app_worker_thread(struct thread_conf **confs)
{
	struct rte_mbuf *mbufs[burst_conf.ring_burst];
	struct thread_conf *conf;
	int conf_idx = 0;

	while ((conf = confs[conf_idx])) {
		/*
		uint32_t nb_pkt;
		uint32_t tx_port = conf->tx_port;

		nb_pkt = rte_ring_sc_dequeue_burst(conf->rx_ring,
			(void **)mbufs, burst_conf.ring_burst, NULL);
		
		if (likely(nb_pkt)) {
			int nb_sent = rte_sched_port_enqueue(conf->sched_port, mbufs, nb_pkt);
			
			port_statistics[tx_port].load_stats.packets_in += nb_sent;

			APP_STATS_ADD(conf->stat.nb_drop, nb_pkt - nb_sent);
			APP_STATS_ADD(conf->stat.nb_rx, nb_pkt);
		}

		update_backpressure_state(tx_port);

		nb_pkt = rte_sched_port_dequeue(conf->sched_port, mbufs, burst_conf.qos_dequeue, port_statistics[tx_port].subport_capacity);

		if (likely(nb_pkt > 0)) {
			port_statistics[tx_port].load_stats.packets_out += nb_pkt;
			
			uint16_t nb_tx = rte_eth_tx_burst(conf->tx_port, 0,
				mbufs, nb_pkt);
			
			for (uint16_t i = 0; i < nb_pkt; i++) {
				port_statistics[tx_port].load_stats.bytes_out +=
					mbufs[i]->pkt_len;
			}

			if (nb_tx != nb_pkt) {
				rte_pktmbuf_free_bulk(&mbufs[nb_tx],
					nb_pkt - nb_tx);
			}
		}
		*/

		conf_idx++;
		if (confs[conf_idx] == NULL)
			conf_idx = 0;
	}
}
