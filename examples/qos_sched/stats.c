/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <rte_telemetry.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "main.h"

int
qavg_q(uint16_t port_id, uint32_t subport_id, uint32_t pipe_id, uint8_t tc,
		uint8_t q)
{
	struct rte_sched_queue_stats stats;
	struct rte_sched_port *port;
	uint16_t qlen;
	uint32_t count, i, queue_id = 0;
	uint32_t average;

	for (i = 0; i < nb_pfc; i++) {
		if (qos_conf[i].tx_port == port_id)
			break;
	}

	if (i == nb_pfc ||
		subport_id >= port_params.n_subports_per_port ||
		pipe_id >= subport_params[subport_id].n_pipes_per_subport_enabled  ||
		tc >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE ||
		q >= RTE_SCHED_BE_QUEUES_PER_PIPE ||
		(tc < RTE_SCHED_TRAFFIC_CLASS_BE && q > 0))
		return -1;

	port = qos_conf[i].sched_port;
	for (i = 0; i < subport_id; i++)
		queue_id += subport_params[i].n_pipes_per_subport_enabled *
				RTE_SCHED_QUEUES_PER_PIPE;
	if (tc < RTE_SCHED_TRAFFIC_CLASS_BE)
		queue_id += pipe_id * RTE_SCHED_QUEUES_PER_PIPE + tc;
	else
		queue_id += pipe_id * RTE_SCHED_QUEUES_PER_PIPE + tc + q;

	average = 0;
	for (count = 0; count < qavg_ntimes; count++) {
		rte_sched_queue_read_stats(port, queue_id, &stats, &qlen);
		average += qlen;
		usleep(qavg_period);
	}

	average /= qavg_ntimes;

	printf("\nAverage queue size: %" PRIu32 " bytes.\n\n", average);

	return 0;
}

int
qavg_tcpipe(uint16_t port_id, uint32_t subport_id, uint32_t pipe_id,
		uint8_t tc)
{
	struct rte_sched_queue_stats stats;
	struct rte_sched_port *port;
	uint16_t qlen;
	uint32_t count, i, queue_id = 0;
	uint32_t average, part_average;

	for (i = 0; i < nb_pfc; i++) {
		if (qos_conf[i].tx_port == port_id)
			break;
	}

	if (i == nb_pfc || subport_id >= port_params.n_subports_per_port ||
		pipe_id >= subport_params[subport_id].n_pipes_per_subport_enabled ||
		tc >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE)
		return -1;

	port = qos_conf[i].sched_port;

	for (i = 0; i < subport_id; i++)
		queue_id +=
			subport_params[i].n_pipes_per_subport_enabled *
			RTE_SCHED_QUEUES_PER_PIPE;

	queue_id += pipe_id * RTE_SCHED_QUEUES_PER_PIPE + tc;

	average = 0;

	for (count = 0; count < qavg_ntimes; count++) {
		part_average = 0;

		if (tc < RTE_SCHED_TRAFFIC_CLASS_BE) {
			rte_sched_queue_read_stats(port, queue_id,
				&stats, &qlen);
			part_average += qlen;
		} else {
			for (i = 0; i < RTE_SCHED_BE_QUEUES_PER_PIPE; i++) {
				rte_sched_queue_read_stats(port, queue_id + i,
					&stats, &qlen);
				part_average += qlen;
			}
			average += part_average / RTE_SCHED_BE_QUEUES_PER_PIPE;
		}
		usleep(qavg_period);
	}

	average /= qavg_ntimes;

	printf("\nAverage queue size: %" PRIu32 " bytes.\n\n", average);

	return 0;
}

int
qavg_pipe(uint16_t port_id, uint32_t subport_id, uint32_t pipe_id)
{
	struct rte_sched_queue_stats stats;
	struct rte_sched_port *port;
	uint16_t qlen;
	uint32_t count, i, queue_id = 0;
	uint32_t average, part_average;

	for (i = 0; i < nb_pfc; i++) {
		if (qos_conf[i].tx_port == port_id)
			break;
	}

	if (i == nb_pfc ||
		subport_id >= port_params.n_subports_per_port ||
		pipe_id >= subport_params[subport_id].n_pipes_per_subport_enabled)
		return -1;

	port = qos_conf[i].sched_port;

	for (i = 0; i < subport_id; i++)
		queue_id += subport_params[i].n_pipes_per_subport_enabled *
				RTE_SCHED_QUEUES_PER_PIPE;

	queue_id += pipe_id * RTE_SCHED_QUEUES_PER_PIPE;

	average = 0;

	for (count = 0; count < qavg_ntimes; count++) {
		part_average = 0;
		for (i = 0; i < RTE_SCHED_QUEUES_PER_PIPE; i++) {
			rte_sched_queue_read_stats(port, queue_id + i,
				&stats, &qlen);
			part_average += qlen;
		}
		average += part_average / RTE_SCHED_QUEUES_PER_PIPE;
		usleep(qavg_period);
	}

	average /= qavg_ntimes;

	printf("\nAverage queue size: %" PRIu32 " bytes.\n\n", average);

	return 0;
}

int
qavg_tcsubport(uint16_t port_id, uint32_t subport_id, uint8_t tc)
{
	struct rte_sched_queue_stats stats;
	struct rte_sched_port *port;
	uint16_t qlen;
	uint32_t queue_id, count, i, j, subport_queue_id = 0;
	uint32_t average, part_average;

	for (i = 0; i < nb_pfc; i++) {
		if (qos_conf[i].tx_port == port_id)
			break;
	}

	if (i == nb_pfc ||
		subport_id >= port_params.n_subports_per_port ||
		tc >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE)
		return -1;

	port = qos_conf[i].sched_port;

	for (i = 0; i < subport_id; i++)
		subport_queue_id +=
			subport_params[i].n_pipes_per_subport_enabled *
			RTE_SCHED_QUEUES_PER_PIPE;

	average = 0;

	for (count = 0; count < qavg_ntimes; count++) {
		uint32_t n_pipes_per_subport =
			subport_params[subport_id].n_pipes_per_subport_enabled;

		part_average = 0;
		for (i = 0; i < n_pipes_per_subport; i++) {
			if (tc < RTE_SCHED_TRAFFIC_CLASS_BE) {
				queue_id = subport_queue_id +
					i * RTE_SCHED_QUEUES_PER_PIPE + tc;
				rte_sched_queue_read_stats(port, queue_id,
					&stats, &qlen);
				part_average += qlen;
			} else {
				for (j = 0; j < RTE_SCHED_BE_QUEUES_PER_PIPE; j++) {
					queue_id = subport_queue_id +
							i * RTE_SCHED_QUEUES_PER_PIPE +
							tc + j;
					rte_sched_queue_read_stats(port, queue_id,
						&stats, &qlen);
					part_average += qlen;
				}
			}
		}

		if (tc < RTE_SCHED_TRAFFIC_CLASS_BE)
			average += part_average /
				(subport_params[subport_id].n_pipes_per_subport_enabled);
		else
			average += part_average /
				(subport_params[subport_id].n_pipes_per_subport_enabled) *
				RTE_SCHED_BE_QUEUES_PER_PIPE;

		usleep(qavg_period);
	}

	average /= qavg_ntimes;

	printf("\nAverage queue size: %" PRIu32 " bytes.\n\n", average);

	return 0;
}

int
qavg_subport(uint16_t port_id, uint32_t subport_id)
{
	struct rte_sched_queue_stats stats;
	struct rte_sched_port *port;
	uint16_t qlen;
	uint32_t queue_id, count, i, j, subport_queue_id = 0;
	uint32_t average, part_average;

	for (i = 0; i < nb_pfc; i++) {
		if (qos_conf[i].tx_port == port_id)
			break;
	}

	if (i == nb_pfc ||
		subport_id >= port_params.n_subports_per_port)
		return -1;

	port = qos_conf[i].sched_port;

	for (i = 0; i < subport_id; i++)
		subport_queue_id += subport_params[i].n_pipes_per_subport_enabled *
			RTE_SCHED_QUEUES_PER_PIPE;

	average = 0;

	for (count = 0; count < qavg_ntimes; count++) {
		uint32_t n_pipes_per_subport =
			subport_params[subport_id].n_pipes_per_subport_enabled;

		part_average = 0;
		for (i = 0; i < n_pipes_per_subport; i++) {
			queue_id = subport_queue_id + i * RTE_SCHED_QUEUES_PER_PIPE;

			for (j = 0; j < RTE_SCHED_QUEUES_PER_PIPE; j++) {
				rte_sched_queue_read_stats(port, queue_id + j,
					&stats, &qlen);
				part_average += qlen;
			}
		}

		average += part_average /
			(subport_params[subport_id].n_pipes_per_subport_enabled *
			RTE_SCHED_QUEUES_PER_PIPE);
		usleep(qavg_period);
	}

	average /= qavg_ntimes;

	printf("\nAverage queue size: %" PRIu32 " bytes.\n\n", average);

	return 0;
}

int
subport_stat(uint16_t port_id, uint32_t subport_id)
{
	struct rte_sched_subport_stats stats;
	struct rte_sched_port *port;
	uint32_t tc_ov[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint8_t i;

	for (i = 0; i < nb_pfc; i++) {
		if (qos_conf[i].tx_port == port_id)
			break;
	}

	if (i == nb_pfc || subport_id >= port_params.n_subports_per_port)
		return -1;

	port = qos_conf[i].sched_port;
	memset(tc_ov, 0, sizeof(tc_ov));

	rte_sched_subport_read_stats(port, subport_id, &stats, tc_ov);

	printf("\n");
	printf("+----+-------------+-------------+-------------+-------------+-------------+\n");
	printf("| TC |   Pkts OK   |Pkts Dropped |  Bytes OK   |Bytes Dropped|  OV Status  |\n");
	printf("+----+-------------+-------------+-------------+-------------+-------------+\n");

	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		printf("|  %d | %11" PRIu64 " | %11" PRIu64 " | %11" PRIu64 " | %11" PRIu64 " | %11" PRIu32 " |\n",
			i, stats.n_pkts_tc[i], stats.n_pkts_tc_dropped[i],
		stats.n_bytes_tc[i], stats.n_bytes_tc_dropped[i], tc_ov[i]);
		printf("+----+-------------+-------------+-------------+-------------+-------------+\n");
	}
	printf("\n");

	return 0;
}

int
pipe_stat(uint16_t port_id, uint32_t subport_id, uint32_t pipe_id)
{
	struct rte_sched_queue_stats stats;
	struct rte_sched_port *port;
	uint16_t qlen;
	uint8_t i, j;
	uint32_t queue_id = 0;

	for (i = 0; i < nb_pfc; i++) {
		if (qos_conf[i].tx_port == port_id)
			break;
	}

	if (i == nb_pfc ||
		subport_id >= port_params.n_subports_per_port ||
		pipe_id >= subport_params[subport_id].n_pipes_per_subport_enabled)
		return -1;

	port = qos_conf[i].sched_port;
	for (i = 0; i < subport_id; i++)
		queue_id += subport_params[i].n_pipes_per_subport_enabled *
			RTE_SCHED_QUEUES_PER_PIPE;

	queue_id += pipe_id * RTE_SCHED_QUEUES_PER_PIPE;

	printf("\n");
	printf("+----+-------+-------------+-------------+-------------+-------------+-------------+\n");
	printf("| TC | Queue |   Pkts OK   |Pkts Dropped |  Bytes OK   |Bytes Dropped|    Length   |\n");
	printf("+----+-------+-------------+-------------+-------------+-------------+-------------+\n");

	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		if (i < RTE_SCHED_TRAFFIC_CLASS_BE) {
			rte_sched_queue_read_stats(port, queue_id + i, &stats, &qlen);
			printf("|  %d |   %d   | %11" PRIu64 " | %11" PRIu64 " | %11" PRIu64 " | %11" PRIu64 " | %11i |\n",
				i, 0, stats.n_pkts, stats.n_pkts_dropped, stats.n_bytes,
				stats.n_bytes_dropped, qlen);
			printf("+----+-------+-------------+-------------+-------------+-------------+-------------+\n");
		} else {
			for (j = 0; j < RTE_SCHED_BE_QUEUES_PER_PIPE; j++) {
				rte_sched_queue_read_stats(port, queue_id + i + j,
					&stats, &qlen);
				printf("|  %d |   %d   | %11" PRIu64 " | %11" PRIu64 " | %11" PRIu64 " | %11" PRIu64 " | %11i |\n",
					i, j, stats.n_pkts, stats.n_pkts_dropped, stats.n_bytes,
					stats.n_bytes_dropped, qlen);
				printf("+----+-------+-------------+-------------+-------------+-------------+-------------+\n");
			}
		}
	}
	printf("\n");

	return 0;
}

int
telemetry_pending_stats(const char *cmd __rte_unused, const char *params, struct rte_tel_data *d)
{
	uint64_t hz = rte_get_tsc_hz();
	int flow_id = 0;
	int tc_filter = -1; /* -1 = all TCs */
	
	/* optional: params = "0,1" → flow 0, tc 1 */
	if (params)
		sscanf(params, "%d,%d", &flow_id, &tc_filter);
	
	if (flow_id >= (int)nb_pfc)
		return -EINVAL;
	
	struct flow_conf *flow = &qos_conf[flow_id];
	
	rte_tel_data_start_dict(d);

	/* latency histogram bucket edges (ns) — published once so consumers
	 *    can interpret lat_hist[] without re-deriving the log-spacing formula */
	struct rte_tel_data *lat_edges = rte_tel_data_alloc();
	rte_tel_data_start_array(lat_edges, RTE_TEL_UINT_VAL);
	for (int b = 0; b <= PHIST_LAT_BUCKETS; b++) {
		uint64_t edge_ns;
		if (b == PHIST_LAT_BUCKETS)
			edge_ns = (uint64_t)pow(10.0, PHIST_MAX_DECADE_EXP);
		else
			edge_ns = (uint64_t)pow(10.0, PHIST_MIN_DECADE_EXP + (double)b / PHIST_BUCKETS_PER_DECADE);
		rte_tel_data_add_array_uint(lat_edges, edge_ns);
	}
	rte_tel_data_add_dict_container(d, "lat_hist_edges_ns", lat_edges, 0);
	
	for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		if (tc_filter >= 0 && tc != tc_filter) continue;
	
		pending_tc_stats_t *s = &flow->tc_stats[tc];
	
		/* build per-TC dict */
		struct rte_tel_data *tc_d = rte_tel_data_alloc();
		rte_tel_data_start_dict(tc_d);
		
		uint64_t avg_occ = s->occ_samples ? s->occ_sum / s->occ_samples : 0;
	       	uint64_t avg_lat = s->lat_samples ? (s->lat_sum_tsc / s->lat_samples) * 1000000000ULL / hz : 0;
		uint64_t max_lat = (s->lat_max_tsc * 1000000000ULL) / hz;
		
		rte_tel_data_add_dict_uint(tc_d, "avg_occ",       avg_occ);
		rte_tel_data_add_dict_uint(tc_d, "max_occ",       s->occ_max);
		rte_tel_data_add_dict_uint(tc_d, "avg_lat_ns",    avg_lat);
		rte_tel_data_add_dict_uint(tc_d, "max_lat_ns",    max_lat);
		rte_tel_data_add_dict_uint(tc_d, "retry_loss",    s->retry_loss);
		rte_tel_data_add_dict_uint(tc_d, "pkts_tx",       s->pkts_tx_total);
		rte_tel_data_add_dict_uint(tc_d, "pkts_retry",    s->pkts_retry_total);
		
		double cyc_tx    = s->pkts_tx_total ? (double)s->cycles_tx    / s->pkts_tx_total    : 0.0;
		double cyc_retry = s->pkts_retry_total ? (double)s->cycles_retry / s->pkts_retry_total : 0.0;
		rte_tel_data_add_dict_uint(tc_d, "cyc_per_tx",    cyc_tx);
		rte_tel_data_add_dict_uint(tc_d, "cyc_per_retry", cyc_retry);


		/* occupancy histogram */
		struct rte_tel_data *occ_hist = rte_tel_data_alloc();
		rte_tel_data_start_array(occ_hist, RTE_TEL_UINT_VAL);
		for (int b = 0; b < PHIST_OCC_BUCKETS; b++)
			    rte_tel_data_add_array_uint(occ_hist, s->occ_hist[b]);
		rte_tel_data_add_dict_container(tc_d, "occ_hist", occ_hist, 0);

		/* latency histogram */
		struct rte_tel_data *lat_hist = rte_tel_data_alloc();
		rte_tel_data_start_array(lat_hist, RTE_TEL_UINT_VAL);
		for (int b = 0; b < PHIST_LAT_BUCKETS; b++)
			        rte_tel_data_add_array_uint(lat_hist, s->lat_hist[b]);
		rte_tel_data_add_dict_container(tc_d, "lat_hist", lat_hist, 0);

		/* retry histogram */
		struct rte_tel_data *retry_hist = rte_tel_data_alloc();
		rte_tel_data_start_array(retry_hist, RTE_TEL_UINT_VAL);
		for (int b = 0; b < PHIST_RETRY_BUCKETS; b++)
			    rte_tel_data_add_array_uint(retry_hist, s->retry_hist[b]);
		rte_tel_data_add_dict_container(tc_d, "retry_hist", retry_hist, 0);
		
		/* nest under "tc_N" key */
		char key[8];
		snprintf(key, sizeof(key), "tc_%d", tc);
		rte_tel_data_add_dict_container(d, key, tc_d, 0);
	}

	
	return 0;
}


/* ---- /qos/ctrl_stats and /qos/scenario (see ctrl_stats.h) ---- */

static const struct {
	const char *name;
	size_t off;
} cs_counters[] = {
#define CS_C(f) { #f, offsetof(struct ctrl_tc_stats, f) }
	CS_C(active), CS_C(req), CS_C(cap), CS_C(ov), CS_C(deq), CS_C(tx),
	CS_C(sent), CS_C(retried), CS_C(retry_sent), CS_C(dropped),
	CS_C(stalls), CS_C(bound), CS_C(polls), CS_C(freed), CS_C(fb_cyc),
	CS_C(h_lowered), CS_C(cuts),
#undef CS_C
}, cs_gauges[] = {
#define CS_G(f) { #f, offsetof(struct ctrl_tc_stats, f) }
	CS_G(pq), CS_G(q_minus_c), CS_G(u), CS_G(u0), CS_G(h), CS_G(delta),
	CS_G(w),
#undef CS_G
};

static int
parse_flow_id(const char *params)
{
	int flow_id = 0;

	if (params != NULL && *params != '\0' &&
			sscanf(params, "%d", &flow_id) != 1)
		return -1;
	if (flow_id < 0 || flow_id >= (int)nb_pfc)
		return -1;
	return flow_id;
}

/*
 * /qos/ctrl_stats,<flow_id>: one record of run telemetry for one flow
 * (instance). Counters are monotonic; difference two records over "tsc"
 * to get rates. Per-TC values are arrays indexed by TC.
 */
int
telemetry_ctrl_stats(const char *cmd __rte_unused, const char *params,
		struct rte_tel_data *d)
{
	int flow_id = parse_flow_id(params);

	if (flow_id < 0)
		return -EINVAL;

	struct flow_conf *flow = &qos_conf[flow_id];
	const struct ctrl_stats *cs = &flow->cs;

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_uint(d, "tsc", rte_rdtsc());
	rte_tel_data_add_dict_uint(d, "flow", (uint64_t)flow_id);

	/* instance-wide state */
	struct rte_tel_data *inst = rte_tel_data_alloc();

	if (inst == NULL)
		return -ENOMEM;
	rte_tel_data_start_dict(inst);
	rte_tel_data_add_dict_uint(inst, "loops", cs->inst.loops);
	rte_tel_data_add_dict_uint(inst, "sched_enq", cs->inst.sched_enq);
	rte_tel_data_add_dict_uint(inst, "sched_drop", cs->inst.sched_drop);
	rte_tel_data_add_dict_uint(inst, "sched_deq", cs->inst.sched_deq);
	rte_tel_data_add_dict_uint(inst, "rx_ring_drop", cs->rx_ring_drop);
	if (flow->rx_ring != NULL)
		rte_tel_data_add_dict_uint(inst, "rx_ring",
				rte_ring_count(flow->rx_ring));
	if (flow->mbuf_pool != NULL) {
		rte_tel_data_add_dict_uint(inst, "mp_avail",
				rte_mempool_avail_count(flow->mbuf_pool));
		rte_tel_data_add_dict_uint(inst, "mp_inuse",
				rte_mempool_in_use_count(flow->mbuf_pool));
	}
	rte_tel_data_add_dict_container(d, "inst", inst, 0);

	/* per-TC counters (uint) and gauges (int, -1 = undefined) */
	struct rte_tel_data *tc = rte_tel_data_alloc();

	if (tc == NULL)
		return -ENOMEM;
	rte_tel_data_start_dict(tc);
	for (size_t i = 0; i < RTE_DIM(cs_counters); i++) {
		struct rte_tel_data *a = rte_tel_data_alloc();

		if (a == NULL)
			break;
		rte_tel_data_start_array(a, RTE_TEL_UINT_VAL);
		for (int t = 0; t < CS_N_TC; t++)
			rte_tel_data_add_array_uint(a, *(const uint64_t *)
				((const char *)&cs->tc[t] + cs_counters[i].off));
		rte_tel_data_add_dict_container(tc, cs_counters[i].name, a, 0);
	}
	for (size_t i = 0; i < RTE_DIM(cs_gauges); i++) {
		struct rte_tel_data *a = rte_tel_data_alloc();

		if (a == NULL)
			break;
		rte_tel_data_start_array(a, RTE_TEL_INT_VAL);
		for (int t = 0; t < CS_N_TC; t++)
			rte_tel_data_add_array_int(a, *(const int64_t *)
				((const char *)&cs->tc[t] + cs_gauges[i].off));
		rte_tel_data_add_dict_container(tc, cs_gauges[i].name, a, 0);
	}

	/*
	 * Reference TxQ occupancy, read here (control thread) and not in the
	 * data path, so it costs the worker nothing. -1 where the PMD has no
	 * queue count (e.g. ice).
	 */
	struct rte_tel_data *qc = rte_tel_data_alloc();

	if (qc != NULL) {
		rte_tel_data_start_array(qc, RTE_TEL_INT_VAL);
		for (int t = 0; t < CS_N_TC; t++) {
			int c = t < N_TC ?
				rte_eth_tx_queue_count(flow->tx_port,
					flow->txq_base + app_tc2q[t]) : -1;

			rte_tel_data_add_array_int(qc, c < 0 ? -1 : c);
		}
		rte_tel_data_add_dict_container(tc, "txq_count", qc, 0);
	}
	rte_tel_data_add_dict_container(d, "tc", tc, 0);

	return 0;
}

/*
 * /qos/scenario: static configuration of this run, queried once. Reads
 * back what the PMD actually configured (TxQ depth, rs/free thresholds),
 * not only what was requested on the command line.
 */
int
telemetry_scenario(const char *cmd __rte_unused,
		const char *params __rte_unused, struct rte_tel_data *d)
{
	char buf[RTE_TEL_MAX_STRING_LEN];

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_string(d, "mode", mixed_mode_name());
	snprintf(buf, sizeof(buf), "%s", cfg_profile ? cfg_profile : "");
	rte_tel_data_add_dict_string(d, "cfg_profile", buf);
	rte_tel_data_add_dict_string(d, "build", __DATE__ " " __TIME__);
	rte_tel_data_add_dict_uint(d, "ctrl_stats_version", CTRL_STATS_VERSION);
	rte_tel_data_add_dict_uint(d, "tsc_hz", rte_get_tsc_hz());
	rte_tel_data_add_dict_uint(d, "tsc", rte_rdtsc());
	rte_tel_data_add_dict_uint(d, "nb_pfc", nb_pfc);
	rte_tel_data_add_dict_string(d, "pf_tree", pf_tree_name());
	if (pf_conf.shape != PF_TREE_OFF) {
		struct rte_tel_data *m = rte_tel_data_alloc();

		rte_tel_data_add_dict_uint(d, "pf_rate_mbps",
				(uint64_t)(pf_conf.rate_gbps * 1000));
		if (m != NULL) {
			rte_tel_data_start_array(m, RTE_TEL_UINT_VAL);
			for (int t = 0; t < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; t++)
				rte_tel_data_add_array_uint(m, app_tc2q[t]);
			rte_tel_data_add_dict_container(d, "pf_tc2q", m, 0);
		}
	}
	rte_tel_data_add_dict_uint(d, "n_tc", CS_N_TC);

	rte_tel_data_add_dict_uint(d, "rx_desc", ring_conf.rx_size);
	rte_tel_data_add_dict_uint(d, "sw_ring", ring_conf.ring_size);
	rte_tel_data_add_dict_uint(d, "tx_desc", ring_conf.tx_size);
	rte_tel_data_add_dict_uint(d, "rx_burst", burst_conf.rx_burst);
	rte_tel_data_add_dict_uint(d, "ring_burst", burst_conf.ring_burst);
	rte_tel_data_add_dict_uint(d, "qos_dequeue", burst_conf.qos_dequeue);
	rte_tel_data_add_dict_uint(d, "tx_burst", burst_conf.tx_burst);
	rte_tel_data_add_dict_int(d, "mp_size", mp_size);
	rte_tel_data_add_dict_uint(d, "pending_max", PENDING_MAX);
	rte_tel_data_add_dict_uint(d, "cbc_poll_us", cbc_poll_us);
	rte_tel_data_add_dict_uint(d, "rej_add_step", rej_add_step);
	rte_tel_data_add_dict_uint(d, "rej_grow_streak", rej_grow_streak);

	rte_tel_data_add_dict_uint(d, "port_rate_Bps", port_params.rate);
	rte_tel_data_add_dict_uint(d, "n_subports", port_params.n_subports_per_port);
	rte_tel_data_add_dict_uint(d, "n_pipes_per_subport",
			port_params.n_pipes_per_subport);
	rte_tel_data_add_dict_uint(d, "pipes_enabled",
			subport_params[0].n_pipes_per_subport_enabled);

	struct rte_tel_data *qs = rte_tel_data_alloc();

	if (qs != NULL) {
		rte_tel_data_start_array(qs, RTE_TEL_UINT_VAL);
		for (int t = 0; t < CS_N_TC; t++)
			rte_tel_data_add_array_uint(qs, subport_params[0].qsize[t]);
		rte_tel_data_add_dict_container(d, "hqos_qsize", qs, 0);
	}

	/*
	 * One dict per flow (instance), keyed "flow_<i>": telemetry arrays
	 * can only hold scalars, not dicts.
	 */
	for (uint32_t i = 0; i < nb_pfc; i++) {
		struct flow_conf *f = &qos_conf[i];
		struct rte_tel_data *fd = rte_tel_data_alloc();
		struct rte_eth_dev_info info;
		struct rte_eth_txq_info qi;

		if (fd == NULL)
			break;
		rte_tel_data_start_dict(fd);
		rte_tel_data_add_dict_uint(fd, "flow", i);
		rte_tel_data_add_dict_uint(fd, "rx_port", f->rx_port);
		rte_tel_data_add_dict_uint(fd, "tx_port", f->tx_port);
		rte_tel_data_add_dict_uint(fd, "rx_core", f->rx_core);
		rte_tel_data_add_dict_uint(fd, "wt_core", f->wt_core);
		rte_tel_data_add_dict_uint(fd, "tx_core", f->tx_core);
		rte_tel_data_add_dict_uint(fd, "rx_queue", f->rx_queue);
		rte_tel_data_add_dict_uint(fd, "txq_base", f->txq_base);
		if (rte_eth_dev_info_get(f->tx_port, &info) == 0 &&
				info.driver_name != NULL)
			rte_tel_data_add_dict_string(fd, "pmd", info.driver_name);
		if (rte_eth_tx_queue_info_get(f->tx_port, f->txq_base, &qi) == 0) {
			rte_tel_data_add_dict_int(fd, "txq_nb_desc", qi.nb_desc);
			rte_tel_data_add_dict_int(fd, "tx_rs_thresh",
					qi.conf.tx_rs_thresh);
			rte_tel_data_add_dict_int(fd, "tx_free_thresh",
					qi.conf.tx_free_thresh);
		} else {
			rte_tel_data_add_dict_int(fd, "txq_nb_desc", -1);
		}
		snprintf(buf, sizeof(buf), "flow_%u", i);
		rte_tel_data_add_dict_container(d, buf, fd, 0);
	}

	return 0;
}
