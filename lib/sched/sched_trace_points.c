/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#include <rte_trace_point_register.h>

#include "sched_trace.h"

/* Eventdev trace points */
RTE_TRACE_POINT_REGISTER(rte_sched_trace_configure,
	lib.sched.configure)

