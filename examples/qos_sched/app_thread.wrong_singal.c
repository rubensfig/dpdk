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

/* Track when BP was activated (for time-based recovery) */
static uint64_t bp_activation_time[RTE_MAX_ETHPORTS][N_TC] = {0};

static inline void update_backpressure_state(uint16_t port) {
	struct rte_port_statistics *stats = &port_statistics[port];
	uint64_t now = rte_get_tsc_cycles();
	uint64_t elapsed = now - stats->last_check_tsc;
	uint64_t check_interval = (stats->tsc_hz * BP_CHECK_INTERVAL_US) / 1000000;
	
	if (elapsed < check_interval)
	return;
	
	stats->last_check_tsc = now;
	
	/* Calculate RX delta */
	uint64_t rx_now = stats->rx;
	uint64_t rx_delta = rx_now - stats->last_rx;
	stats->last_rx = rx_now;
	
	for (int tc = 0; tc < N_TC; tc++) {

	/* ---------------------------
	*      * 0. Extract congestion signals
	*           * --------------------------- */
	
	uint64_t dropped = __atomic_load_n(&stats->dropped[tc], __ATOMIC_ACQUIRE);
	uint64_t new_drops =
	(dropped >= stats->last_dropped[tc]) ?
	(dropped - stats->last_dropped[tc]) :
	dropped;
	stats->last_dropped[tc] = dropped;
	
	double inst_drop_rate =
	(rx_delta > 0) ? ((double)new_drops / (double)rx_delta) : 0.0;
	double drop_rate_pct = inst_drop_rate * 100.0;
	
	/* EWMA smoothing */
	stats->cong_ewma[tc] =
	BP_EWMA_ALPHA * inst_drop_rate +
	(1.0 - BP_EWMA_ALPHA) * stats->cong_ewma[tc];
	
	/* Persistent congestion = ANY of these */
	bool persistent_congestion =
	(new_drops > 0) ||
	(stats->cong_ewma[tc] >= BP_PERSISTENT_THRESH);


	/* ---------------------------
	*      * 1. RUN THE FSM
	*           * --------------------------- */
	
	switch (stats->bp_state[tc]) {
	
	/* ---------------------------------------------------------
	*      * STATE 1 — INACTIVE (normal, full capacity)
	*           * --------------------------------------------------------- */
	case BP_INACTIVE:
	if (persistent_congestion) {
	
	RTE_LOG(INFO, APP,
	"Port %u TC %d: BP ACTIVATED (EWMA=%.5f drop_rate=%.4f%%)\n",
	port, tc, stats->cong_ewma[tc], drop_rate_pct);
	
	stats->bp_state[tc]     = BP_REDUCING;
	stats->state_enter_time[tc] = now;
	stats->subport_capacity[tc] = 90;  /* warm-start */
	stats->zero_drop_start_time[tc] = 0;
	}
	break;
	
	
	/* ---------------------------------------------------------
	*      * STATE 2 — REDUCING (aggressive capacity cuts)
	*           * --------------------------------------------------------- */
	case BP_REDUCING:
	
	if (persistent_congestion) {
	/* aggressive cut: +2% plus scaled by drop rate */
	uint32_t reduction = RTE_MIN(
	10,
	(uint32_t)(drop_rate_pct * 2 + 2)
	);
	
	if (stats->subport_capacity[tc] > BP_ABSOLUTE_MIN_PCT)
	stats->subport_capacity[tc] -= reduction;
	
	if (stats->subport_capacity[tc] < BP_ABSOLUTE_MIN_PCT)
	stats->subport_capacity[tc] = BP_ABSOLUTE_MIN_PCT;
	
	stats->zero_drop_start_time[tc] = 0;
	}
	else {
	/* No new congestion → start stability timer */
	if (stats->zero_drop_start_time[tc] == 0)
	stats->zero_drop_start_time[tc] = now;
	
	uint64_t stable_duration = now - stats->zero_drop_start_time[tc];
	uint64_t min_stable =
	(stats->tsc_hz * BP_ZERO_DROP_WINDOW_US) / 1e6;
	
	if (stable_duration >= min_stable) {
	RTE_LOG(INFO, APP,
	"Port %u TC %d: Transition REDUCING → HOLDING\n",
	port, tc);
	
	stats->bp_state[tc] = BP_HOLDING;
	stats->state_enter_time[tc] = now;
	}
	}
	break;
	
	
	/* ---------------------------------------------------------
	*      * STATE 3 — HOLDING (wait for stability before recovering)
	*           * --------------------------------------------------------- */
	case BP_HOLDING:
	
	if (persistent_congestion) {
	/* congestion reappears → go back to reduction */
	RTE_LOG(INFO, APP,
	"Port %u TC %d: Drops during HOLD → REDUCING\n",
	port, tc);
	
	stats->bp_state[tc]         = BP_REDUCING;
	stats->state_enter_time[tc] = now;
	stats->zero_drop_start_time[tc] = 0;
	
	} else {
	
	uint64_t held_duration = now - stats->state_enter_time[tc];
	uint64_t min_hold =
	(stats->tsc_hz * BP_RECOVERY_TIME_US) / 1e6;
	
	if (held_duration >= min_hold) {
	
	RTE_LOG(INFO, APP,
	"Port %u TC %d: HOLD → RECOVERING (cap=%u%%)\n",
	port, tc, stats->subport_capacity[tc]);
	
	stats->bp_state[tc]         = BP_RECOVERING;
	stats->state_enter_time[tc] = now;
	}
	}
	break;
	
	
	/* ---------------------------------------------------------
	*      * STATE 4 — RECOVERING (ramp capacity up again)
	*           * --------------------------------------------------------- */
	case BP_RECOVERING:
	
	if (new_drops > 0) {
	
	RTE_LOG(INFO, APP,
	"Port %u TC %d: Drops during RECOVERY → REDUCING\n",
	port, tc);
	
	stats->bp_state[tc]         = BP_REDUCING;
	stats->state_enter_time[tc] = now;
	stats->zero_drop_start_time[tc] = 0;
	
	} else {
	/* slow upward ramp */
	stats->subport_capacity[tc] += BP_RECOVERY_STEP_PCT;
	
	if (stats->subport_capacity[tc] >= 100) {
	stats->subport_capacity[tc] = 100;
	stats->bp_state[tc]         = BP_INACTIVE;
	
	RTE_LOG(INFO, APP,
	"Port %u TC %d: BP DEACTIVATED (100%% restored)\n",
	port, tc);
	}
	}
	break;
	} /* switch */
	
	} /* for tc */


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

       			if (likely(nb_rx > 0)) {
				__atomic_add_fetch(&port_statistics[conf->rx_port].rx, nb_rx, __ATOMIC_RELAXED);
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
	int tx_port;

	while ((conf = confs[conf_idx])) {
		nb_pkts = rte_ring_sc_dequeue_burst(conf->tx_ring, (void **)mbufs,
					burst_conf.qos_dequeue, NULL);
		uint16_t nb_tx = 0;
		tx_port = conf->tx_port;
		if (likely(nb_pkts != 0)) {
			for(int i = 0; i < nb_pkts; i++) {
				int tx_queue = mbufs[i]->hash.sched.traffic_class;

				if (tx_queue > N_TX_QUEUES) {
					tx_queue = 1;	
				}

				buffer = tx_buffer[tx_port][tx_queue];
					
				nb_tx += rte_eth_tx_buffer(tx_port, tx_queue, buffer, mbufs[i]);
			}

			// nb_tx = rte_eth_tx_burst(conf->tx_port, 0, mbufs, nb_pkts);
			
			// if (nb_pkts != nb_tx) {
			// 	APP_STATS_ADD(conf->stat.nb_drop, port_statistics[tx_port].dropped);
			//   	rte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_pkts - nb_tx);
			// }
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
	uint16_t tx_port;
	int bp = 0;

	while ((conf = confs[conf_idx])) {
		uint32_t nb_pkt;
		tx_port = conf->tx_port;

		/* Read packet from the ring */
		nb_pkt = rte_ring_sc_dequeue_burst(conf->rx_ring, (void **)mbufs,
					burst_conf.ring_burst, NULL);
		if (likely(nb_pkt)) {
			int nb_sent = rte_sched_port_enqueue(conf->sched_port, mbufs,
					nb_pkt);

			APP_STATS_ADD(conf->stat.nb_drop, nb_pkt - nb_sent);
			APP_STATS_ADD(conf->stat.nb_rx, nb_pkt);
		}

		update_backpressure_state(tx_port);
		// printf("tx_port %d %d\n", tx_port, port_statistics[tx_port].backpressure_active);
		nb_pkt = rte_sched_port_dequeue(conf->sched_port, mbufs,
					burst_conf.qos_dequeue, port_statistics[tx_port].subport_capacity);
					// burst_conf.qos_dequeue, bp);

		if (likely(nb_pkt > 0))
			while (rte_ring_sp_enqueue_bulk(conf->tx_ring,
					(void **)mbufs, nb_pkt, NULL) == 0)
				; /* empty body */

		conf_idx++;
		if (confs[conf_idx] == NULL)
			conf_idx = 0;
	}
}


void
app_mixed_thread(struct thread_conf **confs)
{
	struct rte_mbuf *mbufs[burst_conf.ring_burst];
	struct thread_conf *conf;
	int conf_idx = 0;
	uint16_t tx_port;

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
					burst_conf.qos_dequeue, true);
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
