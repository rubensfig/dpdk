/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _MAIN_H_
#define _MAIN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_sched.h>

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/*
 * Configurable number of RX/TX ring descriptors
 */
#define APP_INTERACTIVE_DEFAULT 0

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

#define N_TX_QUEUES 2
#define N_TC 2

struct thread_stat
{
	uint64_t nb_rx;
	uint64_t nb_drop;
};

/* Backpressure tuning parameters */
/* Backpressure tuning parameters */
#define BP_CHECK_INTERVAL_US        10          /* Check frequency */
#define BP_ACTIVATE_THRESHOLD       0.001       /* 0.1% to activate */
#define BP_ZERO_DROP_WINDOW_US      100000      /* 100ms zero-drop window before recovery */
#define BP_RECOVERY_TIME_US         1000000     /* 1s hold time before recovery starts */

#define BP_ABSOLUTE_MIN_PCT         50          /* Never reduce below 20% */
#define BP_RECOVERY_STEP_PCT        2           /* Slow recovery: +2% per interval */

/* Derived from existing constants, kept for compatibility */
#define BP_CAPACITY_MIN_PCT         30          /* Used if needed for safe recovery min */

/* Global per-TC drop counters (aggregated across all ports) */
struct tc_statistics {
	uint64_t dropped[N_TC];  /* Atomically updated drop counts per TC */
} __rte_cache_aligned;

extern struct tc_statistics tc_stats;

typedef enum {
	BP_INACTIVE,      /* Normal operation, full capacity */
	BP_REDUCING,      /* Actively reducing capacity due to drops */
	BP_HOLDING,       /* Reduced capacity, waiting for stability */
	BP_RECOVERING     /* Gradually increasing capacity back */
} bp_state_t;

/* Per-port statistics for backpressure mechanism */
struct rte_port_statistics {
	uint64_t last_dropped[N_TC];
	uint64_t dropped[N_TC];
	uint64_t dropped_retry[N_TC];
	uint64_t last_tx[N_TC];
	uint64_t tx[N_TC];
	uint64_t last_rx;
	uint64_t rx;
	uint64_t last_check_tsc;
	uint64_t tsc_hz;
	bool bp_active[N_TC];
	uint32_t subport_capacity[N_TC];
	uint64_t last_drop_tsc[N_TC];
	uint64_t state_enter_time[N_TC];
	bp_state_t bp_state[N_TC];
	uint64_t zero_drop_start_time[N_TC];

} __rte_cache_aligned;

/* TX buffer callback context with TC information */
struct tx_callback_ctx {
	uint16_t portid;  /* Port ID for logging/debugging */
	uint8_t tc_id;    /* Traffic class ID (maps to queue ID) */
};

extern struct tx_callback_ctx tx_ctx[RTE_MAX_ETHPORTS][N_TX_QUEUES];
extern struct rte_port_statistics port_statistics[RTE_MAX_ETHPORTS];

void tx_buffer_count_callback(struct rte_mbuf **pkts, uint16_t unsent, void *userdata);


struct thread_conf
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
} __rte_cache_aligned;


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

#ifdef __cplusplus
}
#endif

#endif /* _MAIN_H_ */
