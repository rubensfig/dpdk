/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef SCHED_TRACE_H
#define SCHED_TRACE_H

/**
 * @file
 *
 * API for sched trace support
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_trace_point.h>

#include "rte_eventdev.h"

RTE_TRACE_POINT(
	rte_sched_trace_configure,
	RTE_TRACE_POINT_ARGS(const char * src),
	rte_trace_point_emit_u8(dev_id);
	rte_trace_point_emit_u32(dev_conf->dequeue_timeout_ns);
	rte_trace_point_emit_i32(dev_conf->nb_events_limit);
	rte_trace_point_emit_u8(dev_conf->nb_event_queues);
	rte_trace_point_emit_u8(dev_conf->nb_event_ports);
	rte_trace_point_emit_u32(dev_conf->nb_event_queue_flows);
	rte_trace_point_emit_u32(dev_conf->nb_event_port_dequeue_depth);
	rte_trace_point_emit_u32(dev_conf->nb_event_port_enqueue_depth);
	rte_trace_point_emit_u32(dev_conf->event_dev_cfg);
	rte_trace_point_emit_u8(dev_conf->nb_single_link_event_port_queues);
	rte_trace_point_emit_int(rc);
)

#ifdef __cplusplus
}
#endif

#endif /* SCHED_TRACE_H */
