/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _MAIN_H_
#define _MAIN_H_

#include <stdbool.h>
#include <rte_sched.h>
#include "pending_stats.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/*
 * Configurable number of RX/TX ring descriptors
 */
#define APP_INTERACTIVE_DEFAULT 0

/*
 * Mixed-thread variant (backpressure scheme), selected at run time with
 * --mode <name>; see mixed_mode_list(). The default can still be chosen at
 * build time with the old flags, e.g. -DMIXED_THREAD_CBC=1, or directly with
 * -DMIXED_MODE_DEFAULT=MIXED_MODE_CBC.
 */
#if defined(MIXED_THREAD_PAB_COMP) || defined(MIXED_THREAD_PAB_BQL)
#error "MIXED_THREAD_PAB_COMP/PAB_BQL were renamed to MIXED_THREAD_QBC/CBC"
#endif

enum mixed_mode {
	MIXED_MODE_NONE = 0,		/* upstream qos_sched, no backpressure */
	MIXED_MODE_QBC,			/* Queue Occupancy-Based Capacity (Alg. 2) */
	MIXED_MODE_CBC,			/* Completion-Based Capacity (Alg. 1) */
	MIXED_MODE_PRIOBP,
	MIXED_MODE_PRIOBP_STATS,
	MIXED_MODE_AGGBP,
	MIXED_MODE_PERTCDEQUEUE,
	MIXED_MODE_PRIOPROP,
	MIXED_MODE_MAX
};

#ifndef MIXED_MODE_DEFAULT
#if defined(MIXED_THREAD_CBC) && MIXED_THREAD_CBC
#define MIXED_MODE_DEFAULT MIXED_MODE_CBC
#elif defined(MIXED_THREAD_PRIOBP) && MIXED_THREAD_PRIOBP
#define MIXED_MODE_DEFAULT MIXED_MODE_PRIOBP
#elif defined(MIXED_THREAD_PRIOBP_STATS) && MIXED_THREAD_PRIOBP_STATS
#define MIXED_MODE_DEFAULT MIXED_MODE_PRIOBP_STATS
#elif defined(MIXED_THREAD_AGGBP) && MIXED_THREAD_AGGBP
#define MIXED_MODE_DEFAULT MIXED_MODE_AGGBP
#elif defined(MIXED_THREAD_PERTCDEQUEUE) && MIXED_THREAD_PERTCDEQUEUE
#define MIXED_MODE_DEFAULT MIXED_MODE_PERTCDEQUEUE
#elif defined(MIXED_THREAD_PRIOPROP) && MIXED_THREAD_PRIOPROP
#define MIXED_MODE_DEFAULT MIXED_MODE_PRIOPROP
#else
#define MIXED_MODE_DEFAULT MIXED_MODE_QBC
#endif
#endif

/* CBC completion poll period T_poll in us (--cbc-poll overrides) */
#ifndef CBC_POLL_US
#define CBC_POLL_US 10u
#endif

extern enum mixed_mode mixed_mode;
extern uint32_t cbc_poll_us;
int mixed_mode_parse(const char *name);
const char *mixed_mode_name(void);
const char *mixed_mode_list(void);
bool mixed_mode_has_tc_stats(void);

#define APP_RX_DESC_DEFAULT 1024
#define APP_TX_DESC_DEFAULT 1024

#define APP_RING_SIZE (8*1024)
#define NB_MBUF   (2*1024*1024)

#define MAX_PKT_RX_BURST 64
#define PKT_ENQUEUE 64
#define PKT_DEQUEUE 63
#define MAX_PKT_TX_BURST 64

#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */

#define TX_PTHRESH 36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define MAX_DATA_STREAMS RTE_MAX_LCORE/2
#define MAX_SCHED_SUBPORTS		8
// #define MAX_SCHED_PIPES			65536
#define MAX_SCHED_PIPES			4096
#define MAX_SCHED_PIPE_PROFILES		256
#define MAX_SCHED_SUBPORT_PROFILES	8

#ifndef APP_COLLECT_STAT
#define APP_COLLECT_STAT		1
#endif

#if APP_COLLECT_STAT
#define APP_STATS_ADD(stat,val) (stat) += (val)
#else
#define APP_STATS_ADD(stat,val) do {(void) (val);} while (0)
#endif

#define APP_QAVG_NTIMES 10
#define APP_QAVG_PERIOD 100

#define N_TX_QUEUES 16
#define N_TC 16

struct thread_stat
{
	uint64_t nb_rx;
	uint64_t nb_tx;
	uint64_t nb_drop;
};


struct __rte_cache_aligned thread_conf
{
	uint16_t rx_port;
	uint16_t tx_port;
	uint16_t rx_queue;
	uint16_t tx_queue;
	struct rte_ring *rx_ring;
	struct rte_ring *tx_ring;
	struct rte_sched_port *sched_port;

#if APP_COLLECT_STAT
	struct thread_stat stat;
#endif
};


struct flow_conf
{
	uint32_t rx_core;
	uint32_t wt_core;
	uint32_t tx_core;
	uint16_t rx_port;
	uint16_t tx_port;
	uint16_t rx_queue;
	uint16_t tx_queue;
	struct rte_ring *rx_ring;
	struct rte_ring *tx_ring;
	struct rte_sched_port *sched_port;
	struct rte_mempool *mbuf_pool;

	struct thread_conf rx_thread;
	struct thread_conf wt_thread;
	struct thread_conf tx_thread;

	pending_tc_stats_t tc_stats[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
};


struct ring_conf
{
	uint32_t rx_size;
	uint32_t ring_size;
	uint32_t tx_size;
};

struct burst_conf
{
	uint16_t rx_burst;
	uint16_t ring_burst;
	uint16_t qos_dequeue;
	uint16_t tx_burst;
};

struct ring_thresh
{
	uint8_t pthresh; /**< Ring prefetch threshold. */
	uint8_t hthresh; /**< Ring host threshold. */
	uint8_t wthresh; /**< Ring writeback threshold. */
};

extern uint8_t interactive;
extern uint32_t qavg_period;
extern uint32_t qavg_ntimes;
extern uint32_t nb_pfc;
extern const char *cfg_profile;
extern int mp_size;
extern struct flow_conf qos_conf[];
extern int app_pipe_to_profile[MAX_SCHED_SUBPORTS][MAX_SCHED_PIPES];

extern struct ring_conf ring_conf;
extern struct burst_conf burst_conf;
extern struct ring_thresh rx_thresh;
extern struct ring_thresh tx_thresh;

extern uint32_t active_queues[RTE_SCHED_QUEUES_PER_PIPE];
extern uint32_t n_active_queues;

extern struct rte_sched_port_params port_params;
extern struct rte_sched_cman_params cman_params;
extern struct rte_sched_subport_params subport_params[MAX_SCHED_SUBPORTS];

extern struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS][N_TX_QUEUES];

int app_parse_args(int argc, char **argv);
int app_init(void);

void prompt(void);
void app_rx_thread(struct thread_conf **qconf);
void app_tx_thread(struct thread_conf **qconf);
void app_worker_thread(struct thread_conf **qconf);
void app_mixed_thread(struct thread_conf **qconf);

void app_stat(void);
int subport_stat(uint16_t port_id, uint32_t subport_id);
int pipe_stat(uint16_t port_id, uint32_t subport_id, uint32_t pipe_id);
int qavg_q(uint16_t port_id, uint32_t subport_id, uint32_t pipe_id,
	   uint8_t tc, uint8_t q);
int qavg_tcpipe(uint16_t port_id, uint32_t subport_id, uint32_t pipe_id,
		uint8_t tc);
int qavg_pipe(uint16_t port_id, uint32_t subport_id, uint32_t pipe_id);
int qavg_tcsubport(uint16_t port_id, uint32_t subport_id, uint8_t tc);
int qavg_subport(uint16_t port_id, uint32_t subport_id);
int
telemetry_pending_stats(const char *cmd __rte_unused, 
		const char *params, struct rte_tel_data *d);


#ifdef __cplusplus
}
#endif

#endif /* _MAIN_H_ */
