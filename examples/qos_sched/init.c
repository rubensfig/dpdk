/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_sched.h>
#include <rte_cycles.h>
#include <rte_string_fns.h>
#include <rte_cfgfile.h>
#include <rte_malloc.h>

#include "main.h"
#include "cfg_file.h"
#include "pmdlink.h"

uint32_t app_numa_mask = 0;
static uint32_t app_inited_port_mask = 0;

int app_pipe_to_profile[MAX_SCHED_SUBPORTS][MAX_SCHED_PIPES];

struct rte_port_statistics port_statistics[RTE_MAX_ETHPORTS];
struct tc_statistics tc_stats;
struct tx_callback_ctx tx_ctx[RTE_MAX_ETHPORTS][N_TX_QUEUES];

#define MAX_NAME_LEN 32

struct ring_conf ring_conf = {
	.rx_size   = APP_RX_DESC_DEFAULT,
	.ring_size = APP_RING_SIZE,
	.tx_size   = APP_TX_DESC_DEFAULT,
};

struct burst_conf burst_conf = {
	.rx_burst    = MAX_PKT_RX_BURST,
	.ring_burst  = PKT_ENQUEUE,
	.qos_dequeue = PKT_DEQUEUE,
	.tx_burst    = MAX_PKT_TX_BURST,
};

struct ring_thresh rx_thresh = {
	.pthresh = RX_PTHRESH,
	.hthresh = RX_HTHRESH,
	.wthresh = RX_WTHRESH,
};

struct ring_thresh tx_thresh = {
	.pthresh = TX_PTHRESH,
	.hthresh = TX_HTHRESH,
	.wthresh = TX_WTHRESH,
};

uint32_t nb_pfc;
const char *cfg_profile = NULL;
int mp_size = NB_MBUF;
struct flow_conf qos_conf[MAX_DATA_STREAMS];

static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

typedef uint16_t port_t;
typedef uint16_t teid_t;


qos_node_t *pmdlink_read_topology(port_t port) {
    struct vf_msg_command *cmd;
    uint8_t *response = NULL;

    cmd = rte_zmalloc("vf_msg_command", sizeof(struct vf_msg_command), 0);

    cmd->opcode = VIRTCHNL_OP_HQOS_TREE_READ;
    cmd->input_buffer = NULL;
    cmd->input_size = 0;
    cmd->output_size = 0;
    cmd->output_buffer = &response;
    rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_USER1, "Sending VIRTCHNL_OP_HQOS_TREE_READ, port=%d\n", port);
    rte_eth_dev_send_vf_msg(port, cmd);

    struct virtchnl_hqos_cfg_list *sched_cfg = (struct virtchnl_hqos_cfg_list *)response;

    qos_node_t *rsp = rte_zmalloc("vf_msg_command", sizeof(qos_node_t) * (1 + sched_cfg->num_elem), 0);

    for (int i = 0; i < sched_cfg->num_elem; i++) {
        if (sched_cfg->cfg[i].teid == 0)
            rte_exit(EXIT_FAILURE, "read_vf_qos_nodes() - zero teid assertion failed\n");

        rsp[i] = (qos_node_t){
            .teid = sched_cfg->cfg[i].teid,
            .parent_teid = sched_cfg->cfg[i].parent_teid,
            .tx_queue_id = sched_cfg->cfg[i].tx_queue_id,
        };
    }
    // set an end marker, teid==0 is not legal/used (protected by previous assertion)
    rsp[sched_cfg->num_elem] = (qos_node_t){
        .teid = 0,
    };
    rte_free(cmd);
    return rsp;
}

void pmdlink_set_shaper(uint16_t port, uint16_t source_teid) {
    struct vf_msg_command *cmd;
    cmd = rte_zmalloc("vf_msg_command", sizeof(struct vf_msg_command), 0);

    uint8_t *response = NULL;

    struct virtchnl_hqos_cfg_list *msg = NULL;
    int len = sizeof(struct virtchnl_hqos_cfg_list *) + (6) * sizeof(struct virtchnl_hqos_cfg *);

    cmd->opcode = VIRTCHNL_OP_HQOS_ELEMS_CONF;
    cmd->input_size = len;
    cmd->output_buffer = &response;
    cmd->output_size = IAVF_AQ_BUF_SZ;

    msg = rte_zmalloc("hqos", len, 0);

    msg->num_elem = 1;
    msg->cfg[0].teid = source_teid;
    // msg->cfg[0].tx_priority = tx_priority;
    msg->cfg[0].tx_max = 10000000;

    cmd->input_buffer = (uint8_t *)msg;

    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "Sending VIRTCHNL_OP_HQOS_ELEMS_CONF, port=%d, source_node=%d, shaper=%d\n", port, source_teid, 10000000);
    rte_eth_dev_send_vf_msg(port, cmd);

    rte_free(msg);
    rte_free(cmd);
}


void pmdlink_node_priority(uint16_t port, uint16_t source_teid, uint16_t tx_priority) {
    struct vf_msg_command *cmd;
    cmd = rte_zmalloc("vf_msg_command", sizeof(struct vf_msg_command), 0);

    uint8_t *response = NULL;

    struct virtchnl_hqos_cfg_list *msg = NULL;
    int len = sizeof(struct virtchnl_hqos_cfg_list *) + (6) * sizeof(struct virtchnl_hqos_cfg *);

    cmd->opcode = VIRTCHNL_OP_HQOS_ELEMS_CONF;
    cmd->input_size = len;
    cmd->output_buffer = &response;
    cmd->output_size = IAVF_AQ_BUF_SZ;

    msg = rte_zmalloc("hqos", len, 0);

    msg->num_elem = 1;
    msg->cfg[0].teid = source_teid;
    msg->cfg[0].tx_priority = tx_priority;
    // msg->cfg[0].tx_max = 1000000;
    // msg->cfg[0].tx_share = 8000000;

    cmd->input_buffer = (uint8_t *)msg;

    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "Sending VIRTCHNL_OP_HQOS_ELEMS_CONF, port=%d, source_node=%d, prio=%d\n", port, source_teid, tx_priority);
    rte_eth_dev_send_vf_msg(port, cmd);

    rte_free(msg);
    rte_free(cmd);
}

void pmdlink_add_node(uint16_t port, uint16_t source_teid, uint16_t tx_priority) {
    struct vf_msg_command *cmd;
    cmd = rte_zmalloc("vf_msg_command", sizeof(struct vf_msg_command), 0);

    uint8_t *response = NULL;

    struct virtchnl_hqos_cfg_list *msg = NULL;
    int len = sizeof(struct virtchnl_hqos_cfg_list *) + (6) * sizeof(struct virtchnl_hqos_cfg *);

    cmd->opcode = VIRTCHNL_OP_HQOS_ELEMS_ADD;
    cmd->input_size = len;
    cmd->output_buffer = &response;
    cmd->output_size = IAVF_AQ_BUF_SZ;

    msg = rte_zmalloc("hqos", len, 0);

    msg->num_elem = 1;
    msg->cfg[0].teid = source_teid;
    msg->cfg[0].tx_priority = tx_priority;
    // msg->cfg[0].tx_share = 8000000;

    cmd->input_buffer = (uint8_t *)msg;

    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "Sending VIRTCHNL_OP_HQOS_ELEMS_ADD, port=%d, source_node=%d, prio=%d\n", port, source_teid, tx_priority);
    rte_eth_dev_send_vf_msg(port, cmd);

    rte_free(msg);
    rte_free(cmd);
}

struct port_hqos_state *port_hqos_table[MAXPORTS];

static void port_hqos_init(uint16_t port) {
    struct port_hqos_state *pht = rte_zmalloc("user qos llapi", sizeof(struct port_hqos_state), 0);
    port_hqos_table[port] = pht;

    qos_node_t *qos_nodes = pmdlink_read_topology(port); // assumes read_vf_qos_nodes() cannot fail
    pht->root = qos_nodes[0].teid;
    pht->binding_count = 0;
    pht->bindings[0] = (struct binding){0, 0}; // end marker set, for avoidance of doubt ;-)
					       //
    uint16_t prio = 7;

    // pmdlink_add_node(port, qos_nodes[0].teid, prio);
    // pmdlink_set_shaper(port, qos_nodes[0].teid);
    for (int i = 0; qos_nodes[i].teid != 0; i++) {
    	printf("port=%d, teid=%d, parent_teid=%d, queue_id?%d\n",port, qos_nodes[i].teid, qos_nodes[i].parent_teid, qos_nodes[i].tx_queue_id);
	if (qos_nodes[i].tx_queue_id != 0) {
		pmdlink_node_priority(port, qos_nodes[i].teid, prio--);
	}
    }
}

void
tx_buffer_count_callback(struct rte_mbuf **pkts, uint16_t unsent,
				void *userdata)
{
	struct tx_callback_ctx *ctx = (struct tx_callback_ctx *)userdata;
	
	__atomic_add_fetch(&port_statistics[ctx->portid].dropped[ctx->tc_id], unsent, __ATOMIC_RELEASE);
//% 	/* NEW: Immediately activate BP when drops occur */
//% 	__atomic_store_n(&port_statistics[ctx->portid].bp_active[ctx->tc_id], 
//% 						true, __ATOMIC_RELEASE);
//		
//	/* Record when this TC last saw drops */
//	__atomic_store_n(&port_statistics[ctx->portid].last_drop_tsc[ctx->tc_id],
//						rte_get_tsc_cycles(), __ATOMIC_RELEASE);
//	
	/* Free unsent packets */
	for (uint16_t i = 0; i < unsent; i++)
		rte_pktmbuf_free(pkts[i]);
}

static int
app_init_port(uint16_t portid, struct rte_mempool *mp, bool hqos_init)
{
	int ret;
	struct rte_eth_link link;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rx_conf;
	struct rte_eth_txconf tx_conf;
	uint16_t rx_size;
	uint16_t tx_size;
	struct rte_eth_conf local_port_conf = port_conf;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	/* check if port already initialized (multistream configuration) */
	if (app_inited_port_mask & (1u << portid))
		return 0;

	memset(&rx_conf, 0, sizeof(struct rte_eth_rxconf));
	rx_conf.rx_thresh.pthresh = rx_thresh.pthresh;
	rx_conf.rx_thresh.hthresh = rx_thresh.hthresh;
	rx_conf.rx_thresh.wthresh = rx_thresh.wthresh;
	rx_conf.rx_free_thresh = 32;
	rx_conf.rx_drop_en = 0;
	rx_conf.rx_deferred_start = 0;

	memset(&tx_conf, 0, sizeof(struct rte_eth_txconf));
	tx_conf.tx_thresh.pthresh = tx_thresh.pthresh;
	tx_conf.tx_thresh.hthresh = tx_thresh.hthresh;
	tx_conf.tx_thresh.wthresh = tx_thresh.wthresh;
	tx_conf.tx_free_thresh = 0;
	tx_conf.tx_rs_thresh = 0;
	tx_conf.tx_deferred_start = 0;
/* init port */
	RTE_LOG(INFO, APP, "Initializing port %"PRIu16"... ", portid);
	fflush(stdout);

	ret = rte_eth_dev_info_get(portid, &dev_info);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			"Error during getting device (port %u) info: %s\n",
			portid, strerror(-ret));

	local_port_conf.rxmode.offloads |=
			RTE_ETH_RX_OFFLOAD_VLAN;
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
	ret = rte_eth_dev_configure(portid, 1, N_TX_QUEUES, &local_port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "Cannot configure device: err=%d, port=%u\n",
			 ret, portid);

	rx_size = ring_conf.rx_size;
	tx_size = ring_conf.tx_size;
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &rx_size, &tx_size);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "rte_eth_dev_adjust_nb_rx_tx_desc: err=%d,port=%u\n",
			 ret, portid);
	ring_conf.rx_size = rx_size;
	ring_conf.tx_size = tx_size;

	/* init one RX queue */
	fflush(stdout);
	rx_conf.offloads = local_port_conf.rxmode.offloads;
	ret = rte_eth_rx_queue_setup(portid, 0, (uint16_t)ring_conf.rx_size,
		rte_eth_dev_socket_id(portid), &rx_conf, mp);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "rte_eth_tx_queue_setup: err=%d, port=%u\n",
			 ret, portid);

	/* init one TX queue */
	fflush(stdout);
	for (int i = 0; i < N_TX_QUEUES; i++) {
		tx_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, i,
			(uint16_t)ring_conf.tx_size, rte_eth_dev_socket_id(portid), &tx_conf);

		int burst = 1;
		// if (i != 0)
		// 	burst = 4;

		tx_buffer[portid][i] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(burst), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid][i] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					portid);

		rte_eth_tx_buffer_init(tx_buffer[portid][i], burst);

		/* Setup context: queue i maps to TC i */
	    	tx_ctx[portid][i].portid = portid;
		tx_ctx[portid][i].tc_id = i;
		    
		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid][i], 
				tx_buffer_count_callback, 
				&tx_ctx[portid][i]);

		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_tx_queue_setup: err=%d, port=%u queue=%d\n",
				 ret, portid, i);
	}

	/* Initialize port statistics and backpressure state */
	memset(&port_statistics[portid], 0, sizeof(struct rte_port_statistics));
	port_statistics[portid].tsc_hz = rte_get_tsc_hz();
	port_statistics[portid].last_check_tsc = rte_get_tsc_cycles();
	
	RTE_LOG(INFO, APP, "Port %u: Backpressure mechanism initialized\n", portid);
	RTE_LOG(INFO, APP, "  Check interval: %u us\n", BP_CHECK_INTERVAL_US);
	RTE_LOG(INFO, APP, "  Activation threshold: %u drops\n", BP_THRESHOLD_RATE);
	RTE_LOG(INFO, APP, "  Recovery threshold: %u drops\n", BP_RECOVERY_RATE);

	/* Start device */
	ret = rte_eth_dev_start(portid);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "rte_pmd_port_start: err=%d, port=%u\n",
			 ret, portid);

	printf("done: ");

	/* get link status */
	ret = rte_eth_link_get(portid, &link);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "rte_eth_link_get: err=%d, port=%u: %s\n",
			 ret, portid, rte_strerror(-ret));

	rte_eth_link_to_str(link_status_text, sizeof(link_status_text), &link);
	printf("%s\n", link_status_text);

	if (hqos_init)
		port_hqos_init(portid);

	/*
	ret = rte_eth_promiscuous_enable(portid);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			"rte_eth_promiscuous_enable: err=%s, port=%u\n",
			rte_strerror(-ret), portid);
	*/

	/* mark port as initialized */
	app_inited_port_mask |= 1u << portid;

	return 0;
}

static struct rte_sched_pipe_params pipe_profiles[MAX_SCHED_PIPE_PROFILES] = {
	{ /* Profile #0 */
		.tb_rate = 305175,
		.tb_size = 1000000,

		.tc_rate = {305175, 305175, 305175, 305175, 305175, 305175,
			305175, 305175, 305175, 305175, 305175, 305175, 305175},
		.tc_period = 40,
		.tc_ov_weight = 1,

		.wrr_weights = {1, 1, 1, 1},
	},
};

static struct rte_sched_subport_profile_params
		subport_profile[MAX_SCHED_SUBPORT_PROFILES] = {
	{
		.tb_rate = 1250000000,
		.tb_size = 1000000,
		.tc_rate = {1250000000, 1250000000, 1250000000, 1250000000,
			1250000000, 1250000000, 1250000000, 1250000000, 1250000000,
			1250000000, 1250000000, 1250000000, 1250000000},
		.tc_period = 10,
	},
};

struct rte_sched_subport_params subport_params[MAX_SCHED_SUBPORTS] = {
	{
		.n_pipes_per_subport_enabled = 65536,
		.qsize = {64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64},
		.pipe_profiles = pipe_profiles,
		.n_pipe_profiles = sizeof(pipe_profiles) /
			sizeof(struct rte_sched_pipe_params),
		.n_max_pipe_profiles = MAX_SCHED_PIPE_PROFILES,
		.cman_params = NULL,
	},
	{
		.n_pipes_per_subport_enabled = 65536,
		.qsize = {64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64},
		.pipe_profiles = pipe_profiles,
		.n_pipe_profiles = sizeof(pipe_profiles) /
			sizeof(struct rte_sched_pipe_params),
		.n_max_pipe_profiles = MAX_SCHED_PIPE_PROFILES,
		.cman_params = NULL,
	},
	{
		.n_pipes_per_subport_enabled = 65536,
		.qsize = {64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64},
		.pipe_profiles = pipe_profiles,
		.n_pipe_profiles = sizeof(pipe_profiles) /
			sizeof(struct rte_sched_pipe_params),
		.n_max_pipe_profiles = MAX_SCHED_PIPE_PROFILES,
		.cman_params = NULL,
	},
	{
		.n_pipes_per_subport_enabled = 65536,
		.qsize = {64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64},
		.pipe_profiles = pipe_profiles,
		.n_pipe_profiles = sizeof(pipe_profiles) /
			sizeof(struct rte_sched_pipe_params),
		.n_max_pipe_profiles = MAX_SCHED_PIPE_PROFILES,
		.cman_params = NULL,
	},
	{
		.n_pipes_per_subport_enabled = 65536,
		.qsize = {64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64},
		.pipe_profiles = pipe_profiles,
		.n_pipe_profiles = sizeof(pipe_profiles) /
			sizeof(struct rte_sched_pipe_params),
		.n_max_pipe_profiles = MAX_SCHED_PIPE_PROFILES,
		.cman_params = NULL,
	},
	{
		.n_pipes_per_subport_enabled = 65536,
		.qsize = {64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64},
		.pipe_profiles = pipe_profiles,
		.n_pipe_profiles = sizeof(pipe_profiles) /
			sizeof(struct rte_sched_pipe_params),
		.n_max_pipe_profiles = MAX_SCHED_PIPE_PROFILES,
		.cman_params = NULL,
	},
	{
		.n_pipes_per_subport_enabled = 65536,
		.qsize = {64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64},
		.pipe_profiles = pipe_profiles,
		.n_pipe_profiles = sizeof(pipe_profiles) /
			sizeof(struct rte_sched_pipe_params),
		.n_max_pipe_profiles = MAX_SCHED_PIPE_PROFILES,
		.cman_params = NULL,
	},
	{
		.n_pipes_per_subport_enabled = 65536,
		.qsize = {64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64},
		.pipe_profiles = pipe_profiles,
		.n_pipe_profiles = sizeof(pipe_profiles) /
			sizeof(struct rte_sched_pipe_params),
		.n_max_pipe_profiles = MAX_SCHED_PIPE_PROFILES,
		.cman_params = NULL,
	},
};

struct rte_sched_port_params port_params = {
	.name = "port_scheduler_0",
	.socket = 0, /* computed */
	.rate = 0, /* computed */
	.mtu = 6 + 6 + 4 + 4 + 2 + 1500,
	.frame_overhead = RTE_SCHED_FRAME_OVERHEAD_DEFAULT,
	.n_subports_per_port = 1,
	.n_subport_profiles = 1,
	.subport_profiles = subport_profile,
	.n_max_subport_profiles = MAX_SCHED_SUBPORT_PROFILES,
	.n_pipes_per_subport = MAX_SCHED_PIPES,
};

static struct rte_sched_port *
app_init_sched_port(uint32_t portid, uint32_t socketid)
{
	static char port_name[32]; /* static as referenced from global port_params*/
	struct rte_eth_link link;
	struct rte_sched_port *port = NULL;
	uint32_t pipe, subport;
	uint32_t pipe_count;
	int err;

	err = rte_eth_link_get(portid, &link);
	if (err < 0)
		rte_exit(EXIT_FAILURE,
			 "rte_eth_link_get: err=%d, port=%u: %s\n",
			 err, portid, rte_strerror(-err));

	port_params.socket = socketid;
	port_params.rate = (uint64_t) link.link_speed * 1000 * 1000 / 8;
	snprintf(port_name, sizeof(port_name), "port_%d", portid);
	port_params.name = port_name;

	port = rte_sched_port_config(&port_params);
	if (port == NULL){
		rte_exit(EXIT_FAILURE, "Unable to config sched port\n");
	}

	for (subport = 0; subport < port_params.n_subports_per_port; subport ++) {
		err = rte_sched_subport_config(port, subport,
				&subport_params[subport],
				0);
		if (err) {
			rte_exit(EXIT_FAILURE, "Unable to config sched "
				 "subport %u, err=%d\n", subport, err);
		}

		uint32_t n_pipes_per_subport =
			subport_params[subport].n_pipes_per_subport_enabled;

		pipe_count = 0;
		for (pipe = 0; pipe < n_pipes_per_subport; pipe++) {
			if (app_pipe_to_profile[subport][pipe] != -1) {
				err = rte_sched_pipe_config(port, subport, pipe,
						app_pipe_to_profile[subport][pipe]);
				if (err) {
					rte_exit(EXIT_FAILURE, "Unable to config sched pipe %u "
							"for profile %d, err=%d\n", pipe,
							app_pipe_to_profile[subport][pipe], err);
				}
				pipe_count++;
			}
		}

		if (pipe_count == 0)
			rte_exit(EXIT_FAILURE, "Error: invalid config, no pipes enabled for sched subport %u\n",
					subport);
	}

	struct rte_sched_subport_params *subport_params_ptr = subport_params;
	printf("App mem footprint: %d Bytes\n", rte_sched_port_get_memory_footprint(&port_params,  &subport_params_ptr));

	return port;
}

static int
app_load_cfg_profile(const char *profile)
{
	int ret  = 0;
	if (profile == NULL)
		return 0;
	struct rte_cfgfile *file = rte_cfgfile_load(profile, 0);
	if (file == NULL)
		rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n", profile);

	ret = cfg_load_port(file, &port_params);
	if (ret)
		goto _app_load_cfg_profile_error_return;

	ret = cfg_load_subport(file, subport_params);
	if (ret)
		goto _app_load_cfg_profile_error_return;

	ret = cfg_load_subport_profile(file, subport_profile);
	if (ret)
		goto _app_load_cfg_profile_error_return;

	ret = cfg_load_pipe(file, pipe_profiles);
	if (ret)
		goto _app_load_cfg_profile_error_return;

	return ret;

_app_load_cfg_profile_error_return:
	rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n", profile);
	rte_cfgfile_close(file);

	return ret;
}

int app_init(void)
{
	uint32_t i;
	char ring_name[MAX_NAME_LEN];
	char pool_name[MAX_NAME_LEN];

	if (rte_eth_dev_count_avail() == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet port - bye\n");

	/* load configuration profile */
	if (app_load_cfg_profile(cfg_profile) != 0)
		rte_exit(EXIT_FAILURE, "Invalid configuration profile\n");

	/* Initialize each active flow */
	for(i = 0; i < nb_pfc; i++) {
		uint32_t socket = rte_lcore_to_socket_id(qos_conf[i].rx_core);
		struct rte_ring *ring;
		struct rte_eth_link link = {0};
		int retry_count = 100, retry_delay = 100; /* try every 100ms for 10 sec */

		snprintf(ring_name, MAX_NAME_LEN, "ring-%u-%u", i, qos_conf[i].rx_core);
		ring = rte_ring_lookup(ring_name);
		if (ring == NULL)
			qos_conf[i].rx_ring = rte_ring_create(ring_name, ring_conf.ring_size,
			 	socket, RING_F_SP_ENQ | RING_F_SC_DEQ);
		else
			qos_conf[i].rx_ring = ring;

		snprintf(ring_name, MAX_NAME_LEN, "ring-%u-%u", i, qos_conf[i].tx_core);
		ring = rte_ring_lookup(ring_name);
		if (ring == NULL)
			qos_conf[i].tx_ring = rte_ring_create(ring_name, ring_conf.ring_size,
				socket, RING_F_SP_ENQ | RING_F_SC_DEQ);
		else
			qos_conf[i].tx_ring = ring;


		/* create the mbuf pools for each RX Port */
		snprintf(pool_name, MAX_NAME_LEN, "mbuf_pool%u", i);
		qos_conf[i].mbuf_pool = rte_pktmbuf_pool_create(pool_name,
			mp_size, burst_conf.rx_burst * 4, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_eth_dev_socket_id(qos_conf[i].rx_port));
		if (qos_conf[i].mbuf_pool == NULL)
			rte_exit(EXIT_FAILURE, "Cannot init mbuf pool for socket %u\n", i);

		app_init_port(qos_conf[i].rx_port, qos_conf[i].mbuf_pool, true);
		app_init_port(qos_conf[i].tx_port, qos_conf[i].mbuf_pool, true);

		rte_eth_link_get(qos_conf[i].tx_port, &link);
		if (link.link_status == 0)
			printf("Waiting for link on port %u\n", qos_conf[i].tx_port);
		while (link.link_status == 0 && retry_count--) {
			rte_delay_ms(retry_delay);
			rte_eth_link_get(qos_conf[i].tx_port, &link);
		}

		qos_conf[i].sched_port = app_init_sched_port(qos_conf[i].tx_port, socket);
	}

	RTE_LOG(INFO, APP, "time stamp clock running at %" PRIu64 " Hz\n",
			 rte_get_timer_hz());

	RTE_LOG(INFO, APP, "Ring sizes: NIC RX = %u, Mempool = %d SW queue = %u,"
			 "NIC TX = %u\n", ring_conf.rx_size, mp_size, ring_conf.ring_size,
			 ring_conf.tx_size);

	RTE_LOG(INFO, APP, "Burst sizes: RX read = %hu, RX write = %hu,\n"
						  "             Worker read/QoS enqueue = %hu,\n"
						  "             QoS dequeue = %hu, Worker write = %hu\n",
		burst_conf.rx_burst, burst_conf.ring_burst, burst_conf.ring_burst,
		burst_conf.qos_dequeue, burst_conf.tx_burst);

	RTE_LOG(INFO, APP, "NIC thresholds RX (p = %hhu, h = %hhu, w = %hhu),"
				 "TX (p = %hhu, h = %hhu, w = %hhu)\n",
		rx_thresh.pthresh, rx_thresh.hthresh, rx_thresh.wthresh,
		tx_thresh.pthresh, tx_thresh.hthresh, tx_thresh.wthresh);
  
	return 0;
}
