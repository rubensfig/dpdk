/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <unistd.h>
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

#define APP_MODE_NONE 0
#define APP_RX_MODE   1
#define APP_WT_MODE   2
#define APP_TX_MODE   4

uint8_t interactive = APP_INTERACTIVE_DEFAULT;
uint32_t qavg_period = APP_QAVG_PERIOD;
uint32_t qavg_ntimes = APP_QAVG_NTIMES;

struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS][N_TX_QUEUES] = { 0 };

/* main processing loop */
static int
app_main_loop(__rte_unused void *dummy)
{
	uint32_t lcore_id;
	uint32_t i, mode;
	uint32_t rx_idx = 0;
	uint32_t wt_idx = 0;
	uint32_t tx_idx = 0;
	struct thread_conf *rx_confs[MAX_DATA_STREAMS];
	struct thread_conf *wt_confs[MAX_DATA_STREAMS];
	struct thread_conf *tx_confs[MAX_DATA_STREAMS];

	memset(rx_confs, 0, sizeof(rx_confs));
	memset(wt_confs, 0, sizeof(wt_confs));
	memset(tx_confs, 0, sizeof(tx_confs));


	mode = APP_MODE_NONE;
	lcore_id = rte_lcore_id();

	for (i = 0; i < nb_pfc; i++) {
		struct flow_conf *flow = &qos_conf[i];

		if (flow->rx_core == lcore_id) {
			flow->rx_thread.rx_port = flow->rx_port;
			flow->rx_thread.tx_port = flow->tx_port;
			flow->rx_thread.rx_ring =  flow->rx_ring;
			flow->rx_thread.rx_queue = flow->rx_queue;
			flow->rx_thread.sched_port = flow->sched_port;

			rx_confs[rx_idx++] = &flow->rx_thread;

			mode |= APP_RX_MODE;
		}
		if (flow->tx_core == lcore_id) {
			flow->tx_thread.rx_port = flow->rx_port;
			flow->tx_thread.tx_port = flow->tx_port;
			flow->tx_thread.tx_ring =  flow->tx_ring;
			flow->tx_thread.tx_queue = flow->tx_queue;

			tx_confs[tx_idx++] = &flow->tx_thread;

			mode |= APP_TX_MODE;
		}
		if (flow->wt_core == lcore_id) {
			flow->wt_thread.rx_ring =  flow->rx_ring;
			flow->wt_thread.tx_ring =  flow->tx_ring;
			flow->wt_thread.tx_port =  flow->tx_port;
			flow->tx_thread.tx_queue = flow->tx_queue;
			flow->wt_thread.sched_port =  flow->sched_port;

			wt_confs[wt_idx++] = &flow->wt_thread;

			mode |= APP_WT_MODE;
		}
	}

	if (mode == APP_MODE_NONE) {
		RTE_LOG(INFO, APP, "lcore %u has nothing to do\n", lcore_id);
		return -1;
	}

	if (mode == (APP_RX_MODE | APP_WT_MODE)) {
		RTE_LOG(INFO, APP, "lcore %u was configured for both RX and WT !!!\n",
				 lcore_id);
		return -1;
	}

	RTE_LOG(INFO, APP, "entering main loop on lcore %u\n", lcore_id);
	/* initialize mbuf memory */
	if (mode == APP_RX_MODE) {
		for (i = 0; i < rx_idx; i++) {
			RTE_LOG(INFO, APP, "flow%u lcoreid%u reading port%u\n",
					i, lcore_id, rx_confs[i]->rx_port);
		}

		app_rx_thread(rx_confs);
	}
	else if (mode == (APP_TX_MODE | APP_WT_MODE)) {
		for (i = 0; i < wt_idx; i++) {
			RTE_LOG(INFO, APP,
				"flow %u lcoreid %u sched+write port %u\n",
					i, lcore_id, wt_confs[i]->tx_port);
		}

		app_mixed_thread(wt_confs);
	}
	else if (mode == APP_TX_MODE) {
		for (i = 0; i < tx_idx; i++) {
			RTE_LOG(INFO, APP, "flow%u lcoreid%u write port%u\n",
					i, lcore_id, tx_confs[i]->tx_port);
		}

		app_tx_thread(tx_confs);
	}
	else if (mode == APP_WT_MODE){
		for (i = 0; i < wt_idx; i++) {
			RTE_LOG(INFO, APP, "flow %u lcoreid %u scheduling \n", i, lcore_id);
		}

		app_worker_thread(wt_confs);
	}

	return 0;
}

void
app_stat(void)
{
	uint32_t i;
	struct rte_eth_stats stats;
	static struct rte_eth_stats rx_stats[MAX_DATA_STREAMS];
	static struct rte_eth_stats tx_stats[MAX_DATA_STREAMS];

	/* print statistics */
	for(i = 0; i < nb_pfc; i++) {
		struct flow_conf *flow = &qos_conf[i];

		rte_eth_stats_get(flow->rx_port, &stats);
		printf("\nRX port %"PRIu16": rx: %"PRIu64 " err: %"PRIu64
				" no_mbuf: %"PRIu64 " missed: %"PRIu64 "\n",
				flow->rx_port,
				stats.ipackets - rx_stats[i].ipackets,
				stats.ierrors - rx_stats[i].ierrors,
				stats.rx_nombuf - rx_stats[i].rx_nombuf,
				stats.imissed - rx_stats[i].imissed);
		memcpy(&rx_stats[i], &stats, sizeof(stats));

		rte_eth_stats_get(flow->tx_port, &stats);
		printf("TX port %"PRIu16": tx: %" PRIu64 " err: %" PRIu64 "\n",
				flow->tx_port,
				stats.opackets - tx_stats[i].opackets,
				stats.oerrors - tx_stats[i].oerrors);
		memcpy(&tx_stats[i], &stats, sizeof(stats));

#if APP_COLLECT_STAT
		printf("-------+------------+------------+\n");
		printf("       |  received  |   dropped  |\n");
		printf("-------+------------+------------+\n");
		printf("  RX   | %10" PRIu64 " | %10" PRIu64 " |\n",
			flow->rx_thread.stat.nb_rx,
			flow->rx_thread.stat.nb_drop);
		printf("QOS+TX | %10" PRIu64 " | %10" PRIu64 " |   pps: %"PRIu64 " \n",
			flow->wt_thread.stat.nb_rx,
			flow->wt_thread.stat.nb_drop,
			flow->wt_thread.stat.nb_rx - flow->wt_thread.stat.nb_drop);
		printf("-------+------------+------------+\n");

#if MIXED_THREAD_PRIOBP_STATS
	uint64_t hz = rte_get_tsc_hz();
	printf("-------+------------ Pending Queue Stats -------------+\n");
	printf("  TC   | avg_occ | max_occ | avg_lat_ns | max_lat_ns | loss | cyc/tx | cyc/retry |\n");
	printf("-------+---------+---------+------------+------------+------+--------+-----------+\n");
	
	for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		pending_tc_stats_t *s = &flow->tc_stats[tc];
	
	double avg_occ   = s->occ_samples ? (double)s->occ_sum / s->occ_samples : 0;
	uint64_t avg_lat = s->lat_samples ? (s->lat_sum_tsc / s->lat_samples) * 1000000000ULL / hz : 0;
	uint64_t max_lat = (s->lat_max_tsc * 1000000000ULL) / hz;
	double cyc_tx    = s->pkts_tx_total ? (double)s->cycles_tx    / s->pkts_tx_total    : 0;
	double cyc_retry = s->pkts_retry_total ? (double)s->cycles_retry / s->pkts_retry_total : 0;
	
	printf("  %2d   | %7.1f | %7u | %10lu | %10lu | %4lu | %6.1f | %9.1f |\n",
		tc, avg_occ, s->occ_max, avg_lat, max_lat, s->retry_loss, cyc_tx, cyc_retry);
	
	/* occupancy histogram */
	if (s->occ_samples && s->occ_max > 0) {
		printf("  occ_hist (bucket=%d slots):\n", PENDING_MAX / PHIST_OCC_BUCKETS);
		for (int b = 0; b < PHIST_OCC_BUCKETS; b++) {

			if (!s->occ_hist[b]) continue;

			printf("    [%4d-%4d]: %lu\n", b * PENDING_MAX / PHIST_OCC_BUCKETS,
			(b + 1) * PENDING_MAX / PHIST_OCC_BUCKETS - 1, s->occ_hist[b]);
		}
	}
	
	/* latency histogram */
	if (s->lat_samples) {
		printf("  lat_hist (ns):\n");

		for (int b = 0; b < PHIST_LAT_BUCKETS; b++) {

			if (!s->lat_hist[b]) continue;
			if (lat_hist_edges_ns[b] == UINT64_MAX)
				printf("    [    >1s]: %lu\n", s->lat_hist[b]);
			else
				printf("    [<%7lu]: %lu\n", lat_hist_edges_ns[b], s->lat_hist[b]);
		}
	}
	
	/* retry histogram */
	if (s->retry_total) {
		printf("  retry_hist:\n");
		for (int b = 0; b < PHIST_RETRY_BUCKETS; b++) {
			if (!s->retry_hist[b]) continue;
			if (b == PHIST_RETRY_BUCKETS - 1)
				printf("    [%d+]: %lu\n", b, s->retry_hist[b]);
			else
				printf("    [%d]:  %lu\n", b, s->retry_hist[b]);
		}
	}
	
	pstats_reset(s);
	}
	printf("-------+---------+---------+------------+------------+------+--------+-----------+\n");
#endif

		memset(&flow->rx_thread.stat, 0, sizeof(struct thread_stat));
		memset(&flow->wt_thread.stat, 0, sizeof(struct thread_stat));
#endif
	}
}

int
main(int argc, char **argv)
{
	int ret;

	ret = app_parse_args(argc, argv);
	if (ret < 0)
		return -1;

	ret = app_init();
	if (ret < 0)
		return -1;

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(app_main_loop, NULL, SKIP_MAIN);

	if (interactive) {
		sleep(1);
		prompt();
	}
	else {
		/* print statistics every second */
		while(1) {
			sleep(1);
			app_stat();
		}
	}

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
