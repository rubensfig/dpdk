/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>

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
#include <rte_tm.h>
#include <rte_telemetry.h>

#include "main.h"
#include "cfg_file.h"
#include "pending_stats.h"
#include "pmdlink.h"

uint32_t app_numa_mask = 0;
static uint32_t app_inited_port_mask = 0;

int app_pipe_to_profile[MAX_SCHED_SUBPORTS][MAX_SCHED_PIPES];

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
    int ret;

    cmd = rte_zmalloc("vf_msg_command", sizeof(struct vf_msg_command), 0);

    cmd->opcode = VIRTCHNL_OP_HQOS_TREE_READ;
    cmd->input_buffer = NULL;
    cmd->input_size = 0;
    cmd->output_size = 0;
    cmd->output_buffer = &response;
    rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_USER1, "Sending VIRTCHNL_OP_HQOS_TREE_READ, port=%d\n", port);
    ret = rte_eth_dev_send_vf_msg(port, cmd);
    rte_free(cmd);

    if (ret != 0 || response == NULL)
        rte_exit(EXIT_FAILURE, "HQOS_TREE_READ failed on port %d: ret=%d\n", port, ret);

    struct virtchnl_hqos_cfg_list *sched_cfg = (struct virtchnl_hqos_cfg_list *)response;

    /* the reply is copied from a buffer of IAVF_AQ_BUF_SZ bytes */
    const int max_elem = 1 + (IAVF_AQ_BUF_SZ - (int)sizeof(struct virtchnl_hqos_cfg_list)) /
                              (int)sizeof(struct virtchnl_hqos_cfg);
    if (sched_cfg->num_elem == 0 || sched_cfg->num_elem > max_elem)
        rte_exit(EXIT_FAILURE, "HQOS_TREE_READ: bad num_elem=%u (max %d)\n",
                 sched_cfg->num_elem, max_elem);

    qos_node_t *rsp = rte_zmalloc("qos_nodes", sizeof(qos_node_t) * (1 + sched_cfg->num_elem), 0);

    printf("HQOS tree, port %d (%u elements):\n", port, sched_cfg->num_elem);
    for (int i = 0; i < sched_cfg->num_elem; i++) {
        struct virtchnl_hqos_cfg *c = &sched_cfg->cfg[i];

        if (c->teid == 0)
            rte_exit(EXIT_FAILURE, "HQOS_TREE_READ: element %d has teid 0 (layout mismatch?)\n", i);

        rsp[i] = (qos_node_t){
            .teid = c->teid,
            .parent_teid = c->parent_teid,
            .node_type = c->node_type,
            .tx_queue_id = 0, /* leaves: set below */
        };
        printf("  [%d] %s teid=%u parent=%u prio=%u weight=%u%s\n", i,
               c->node_type == VIRTCHNL_HQOS_ELEM_TYPE_LEAF ? "leaf" : "node",
               c->teid, c->parent_teid, c->tx_priority, c->tx_weight,
               c->node_type == VIRTCHNL_HQOS_ELEM_TYPE_LEAF ? "  <- leaf" : "");
    }
    // set an end marker, teid==0 is not legal/used (checked above)
    rsp[sched_cfg->num_elem] = (qos_node_t){ .teid = 0 };

    /* The driver sends no queue id. ice gives each new queue to the
     * least-loaded queue group, scanning the groups in tree order
     * (ice_sched_get_free_qgrp), so queues are spread round-robin over the
     * groups: with G groups, the k-th leaf of the g-th group is TX queue
     * k*G + g. Leaves are listed in the order they were attached. */
    {
        uint32_t groups[MAXQUEUES];
        uint16_t filled[MAXQUEUES] = {0};
        int n_groups = 0;

        for (int i = 0; i < sched_cfg->num_elem; i++) {
            if (rsp[i].node_type != VIRTCHNL_HQOS_ELEM_TYPE_LEAF)
                continue;
            int g = 0;
            while (g < n_groups && groups[g] != rsp[i].parent_teid)
                g++;
            if (g == n_groups && n_groups < MAXQUEUES)
                groups[n_groups++] = rsp[i].parent_teid;
        }
        for (int i = 0; i < sched_cfg->num_elem; i++) {
            if (rsp[i].node_type != VIRTCHNL_HQOS_ELEM_TYPE_LEAF)
                continue;
            int g = 0;
            while (groups[g] != rsp[i].parent_teid)
                g++;
            rsp[i].tx_queue_id = filled[g]++ * n_groups + g;
        }
        for (int i = 0; i < sched_cfg->num_elem; i++)
            if (rsp[i].node_type == VIRTCHNL_HQOS_ELEM_TYPE_LEAF)
                printf("  leaf %u (group %u) = TX queue %u\n",
                       rsp[i].teid, rsp[i].parent_teid, rsp[i].tx_queue_id);
    }

    rte_free(response);
    return rsp;
}

static void pmdlink_set_shaper(uint16_t port, uint32_t source_teid) {
    struct vf_msg_command *cmd;
    cmd = rte_zmalloc("vf_msg_command", sizeof(struct vf_msg_command), 0);

    uint8_t *response = NULL;

    struct virtchnl_hqos_cfg_list *msg = NULL;
    int len = sizeof(struct virtchnl_hqos_cfg_list); /* one element */

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
    int ret = rte_eth_dev_send_vf_msg(port, cmd);
    if (ret != 0)
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "opcode %u on teid %u failed: %d (see dmesg on the host)\n",
                cmd->opcode, source_teid, ret);
    if (response)
        rte_free(response);

    rte_free(msg);
    rte_free(cmd);
}


static __rte_unused void pmdlink_node_priority(uint16_t port, uint32_t source_teid, uint16_t tx_priority) {
    struct vf_msg_command *cmd;
    cmd = rte_zmalloc("vf_msg_command", sizeof(struct vf_msg_command), 0);

    uint8_t *response = NULL;

    struct virtchnl_hqos_cfg_list *msg = NULL;
    int len = sizeof(struct virtchnl_hqos_cfg_list); /* one element */

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
    int ret = rte_eth_dev_send_vf_msg(port, cmd);
    if (ret != 0)
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "opcode %u on teid %u failed: %d (see dmesg on the host)\n",
                cmd->opcode, source_teid, ret);
    if (response)
        rte_free(response);

    rte_free(msg);
    rte_free(cmd);
}

static __rte_unused void pmdlink_add_node(uint16_t port, uint32_t source_teid, uint16_t tx_priority) {
    struct vf_msg_command *cmd;
    cmd = rte_zmalloc("vf_msg_command", sizeof(struct vf_msg_command), 0);

    uint8_t *response = NULL;

    struct virtchnl_hqos_cfg_list *msg = NULL;
    int len = sizeof(struct virtchnl_hqos_cfg_list); /* one element */

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
    int ret = rte_eth_dev_send_vf_msg(port, cmd);
    if (ret != 0)
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "opcode %u on teid %u failed: %d (see dmesg on the host)\n",
                cmd->opcode, source_teid, ret);
    if (response)
        rte_free(response);

    rte_free(msg);
    rte_free(cmd);
}

struct port_hqos_state *port_hqos_table[MAXPORTS];

/* ------------------------------------------------------------------------
 * PMDLink (iavf VFs only): strict priority between the TX queues of this VF.
 *
 * TX queue q carries traffic class q (app_thread.c), so queue 0 = TC0 is the
 * most important. On E810, priority only arbitrates between siblings, 7 is
 * served first, and the ice driver ignores priority 0, so a sibling set has
 * 7 usable levels (7..1).
 *
 * ice spreads a VF's queues round-robin over its queue groups, so by default
 * every group mixes classes. To get one strict order over all queues, the
 * leaves are moved so that group j holds queues 7j .. 7j+6:
 *   group j gets priority 7 - j, queue q gets 7 - (q % 7) inside its group.
 * Missing groups are created with ELEMS_ADD. Moves stay inside this VF's
 * subtree, which is all the PF allows; priority across VFs is not possible.
 *
 * The kernel ORs a new priority into the old bits, so run the same
 * configuration every time (or reload ice) to keep the values exact.
 * ------------------------------------------------------------------------ */
#define PMDLINK_LEVELS          7   /* usable priorities per sibling set */
#define PMDLINK_QGRP_MAX_CHILD  8   /* E810 queue-group fan-out */

static int pmdlink_send_one(uint16_t port, uint32_t opcode, const struct virtchnl_hqos_cfg *cfg)
{
    struct vf_msg_command *cmd = rte_zmalloc("vf_msg_command", sizeof(*cmd), 0);
    struct virtchnl_hqos_cfg_list *msg = rte_zmalloc("hqos", sizeof(*msg), 0);
    uint8_t *response = NULL;
    int ret;

    msg->num_elem = 1;
    msg->cfg[0] = *cfg;
    cmd->opcode = opcode;
    cmd->input_buffer = (uint8_t *)msg;
    cmd->input_size = sizeof(*msg);
    cmd->output_buffer = &response;
    cmd->output_size = IAVF_AQ_BUF_SZ;

    ret = rte_eth_dev_send_vf_msg(port, cmd);
    if (ret != 0)
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                "port %u: opcode %u (teid %u, parent %u) failed: %d (see dmesg on the host)\n",
                port, opcode, cfg->teid, cfg->parent_teid, ret);
    if (response)
        rte_free(response);
    rte_free(msg);
    rte_free(cmd);
    return ret;
}

static int pmdlink_move(uint16_t port, uint32_t teid, uint32_t new_parent)
{
    struct virtchnl_hqos_cfg c = { .node_type = VIRTCHNL_HQOS_ELEM_TYPE_LEAF,
                                   .teid = teid, .parent_teid = new_parent };
    return pmdlink_send_one(port, VIRTCHNL_OP_HQOS_ELEMS_MOVE, &c);
}

static int pmdlink_add_group(uint16_t port, uint32_t parent)
{
    struct virtchnl_hqos_cfg c = { .node_type = VIRTCHNL_HQOS_ELEM_TYPE_NODE,
                                   .parent_teid = parent };
    return pmdlink_send_one(port, VIRTCHNL_OP_HQOS_ELEMS_ADD, &c);
}

static int pmdlink_prio(uint16_t port, uint32_t teid, uint32_t prio)
{
    struct virtchnl_hqos_cfg c = { .node_type = VIRTCHNL_HQOS_ELEM_TYPE_NODE,
                                   .teid = teid, .tx_priority = prio };
    return pmdlink_send_one(port, VIRTCHNL_OP_HQOS_ELEMS_CONF, &c);
}

static int find_teid(const uint32_t *v, int n, uint32_t teid)
{
    for (int i = 0; i < n; i++)
        if (v[i] == teid)
            return i;
    return -1;
}

static void port_hqos_init(uint16_t port) {
    struct rte_eth_dev_info dev_info;

    if (rte_eth_dev_info_get(port, &dev_info) != 0 ||
        strcmp(dev_info.driver_name, "net_iavf") != 0)
        return;

    struct port_hqos_state *pht = rte_zmalloc("user qos llapi", sizeof(struct port_hqos_state), 0);
    port_hqos_table[port] = pht;

    qos_node_t *t = pmdlink_read_topology(port);
    pht->root = t[0].teid;
    pht->binding_count = 0;
    pht->bindings[0] = (struct binding){0, 0};

    /* Optional cap on the VF's root node, in kbps. 0 keeps the default
     * (unlimited) tree; the old code set 10000000 = 10 Gb/s here. */
#define PMDLINK_VF_TX_MAX_KBPS 0
    if (PMDLINK_VF_TX_MAX_KBPS)
        pmdlink_set_shaper(port, t[0].teid);

    /* leaves (with their queue ids, from the first read) and queue groups */
    static uint32_t leaf_teid[MAXQUEUES], cur[MAXQUEUES], target[MAXQUEUES];
    static uint16_t leaf_q[MAXQUEUES];
    static uint32_t grp[MAXQUEUES];
    int nl = 0, ng = 0;
    uint32_t grp_parent = 0;

    for (int i = 0; t[i].teid != 0; i++) {
        if (t[i].node_type != VIRTCHNL_HQOS_ELEM_TYPE_LEAF || nl >= MAXQUEUES)
            continue;
        leaf_teid[nl] = t[i].teid;
        leaf_q[nl] = t[i].tx_queue_id;
        cur[nl] = t[i].parent_teid;
        nl++;
        if (find_teid(grp, ng, t[i].parent_teid) < 0)
            grp[ng++] = t[i].parent_teid;
    }
    for (int i = 0; t[i].teid != 0; i++)
        if (ng && t[i].teid == grp[0])
            grp_parent = t[i].parent_teid;
    rte_free(t);

    if (nl == 0 || grp_parent == 0) {
        printf("port=%d: PMDLink: no TX queues found in the tree\n", port);
        return;
    }

    /* 1) enough groups: one per PMDLINK_LEVELS queues */
    int needed = (nl + PMDLINK_LEVELS - 1) / PMDLINK_LEVELS;
    if (needed > 7) {
        printf("port=%d: PMDLink: %d queues need %d groups, at most 7 can be ordered\n",
               port, nl, needed);
        needed = 7;
    }
    while (ng < needed) {
        if (pmdlink_add_group(port, grp_parent) != 0)
            break;
        qos_node_t *t2 = pmdlink_read_topology(port);
        int added = 0;
        for (int i = 0; t2[i].teid != 0 && ng < needed; i++)
            if (t2[i].parent_teid == grp_parent &&
                t2[i].node_type != VIRTCHNL_HQOS_ELEM_TYPE_LEAF &&
                find_teid(grp, ng, t2[i].teid) < 0) {
                grp[ng++] = t2[i].teid;
                added = 1;
            }
        rte_free(t2);
        if (!added)
            break;
    }
    if (ng < needed) {
        printf("port=%d: PMDLink: could only get %d of %d queue groups; "
               "priorities below are approximate\n", port, ng, needed);
        needed = ng;
    }

    /* 2) move each leaf to group q / 7 (overflow queues go to the last group) */
    int cnt[MAXQUEUES] = {0};
    for (int k = 0; k < nl; k++) {
        int g = leaf_q[k] / PMDLINK_LEVELS;
        target[k] = grp[g < needed ? g : needed - 1];
        int cg = find_teid(grp, ng, cur[k]);
        if (cg >= 0)
            cnt[cg]++;
    }

    int moves = 0, failed = 0;
    for (int iter = 0; iter < 4 * nl && !failed; iter++) {
        int misplaced = 0, progress = 0;

        for (int k = 0; k < nl && !failed; k++) {
            if (cur[k] == target[k])
                continue;
            misplaced++;
            int tg = find_teid(grp, ng, target[k]), cg = find_teid(grp, ng, cur[k]);
            if (cnt[tg] >= PMDLINK_QGRP_MAX_CHILD)
                continue;
            if (pmdlink_move(port, leaf_teid[k], target[k]) != 0) {
                failed = 1;
                break;
            }
            cnt[tg]++; cnt[cg]--; cur[k] = target[k];
            moves++; progress = 1; misplaced--;
        }
        if (!misplaced || failed)
            break;
        if (!progress) {
            /* every target is full: park one misplaced leaf in a group with room */
            for (int k = 0; k < nl; k++) {
                if (cur[k] == target[k])
                    continue;
                int cg = find_teid(grp, ng, cur[k]), g;
                for (g = 0; g < ng; g++)
                    if (grp[g] != cur[k] && cnt[g] < PMDLINK_QGRP_MAX_CHILD)
                        break;
                if (g == ng || pmdlink_move(port, leaf_teid[k], grp[g]) != 0) {
                    failed = 1;
                    break;
                }
                cnt[g]++; cnt[cg]--; cur[k] = grp[g]; moves++;
                break;
            }
        }
    }
    printf("port=%d: PMDLink: %d queues, %d groups, %d moves%s\n", port, nl, needed, moves,
           failed ? " (FAILED: queues keep their default groups)" : "");

    /* 3) priorities: groups 7, 6, ...; queues 7..1 inside their group */
    for (int k = 0; k < nl; k++) {
        uint32_t lp = PMDLINK_LEVELS - (leaf_q[k] % PMDLINK_LEVELS);
        int g = find_teid(grp, ng, cur[k]);
        if (!failed && leaf_q[k] >= needed * PMDLINK_LEVELS)
            lp = 1;  /* overflow queues share the lowest level */
        printf("port=%d: queue %u (leaf %u) -> priority %u in group %u (group priority %d)\n",
               port, leaf_q[k], leaf_teid[k], lp, cur[k], 7 - g);
        pmdlink_prio(port, leaf_teid[k], lp);
    }
    for (int g = 0; g < needed; g++)
        pmdlink_prio(port, grp[g], 7 - g);
    if (failed)
        printf("port=%d: WARNING: queues were not regrouped, so strict priority holds for "
               "queue 0 against the rest only\n", port);

    /* 4) read back */
    t = pmdlink_read_topology(port);
    rte_free(t);
}

static int
app_init_port_tm(uint16_t port_id)
{
	struct rte_tm_error error;
	struct rte_tm_shaper_params shaper_params;
	struct rte_tm_node_params node_params;
	const uint32_t root_id       = 1000;
	const uint32_t nonleaf_id[3] = {900, 800, 700};
	const uint32_t nonleaf_parent[3] = {root_id, nonleaf_id[0], nonleaf_id[1]};
	const uint32_t leaf_parent   = nonleaf_id[2]; /* 700, level 3 */
	uint32_t i;
	int ret;

	memset(&error, 0, sizeof(error));

	memset(&shaper_params, 0, sizeof(shaper_params));
	shaper_params.peak.rate = 25000000000 / 8;
	shaper_params.peak.size = 1500;

	ret = rte_tm_shaper_profile_add(port_id, 1, &shaper_params, &error);
	if (ret != 0)
		goto tm_error;

	/* root: node 1000, level 0 */
	memset(&node_params, 0, sizeof(node_params));
	node_params.shaper_profile_id = 1;
	node_params.nonleaf.n_sp_priorities = 0;
	node_params.stats_mask = 1;

	ret = rte_tm_node_add(port_id, root_id, RTE_TM_NODE_ID_NULL,
		0, 1, 0, &node_params, &error);
	if (ret != 0)
		goto tm_error;

	/* nonleaf chain: 900(lvl1) -> 800(lvl2) -> 700(lvl3) -- max depth for cnxk */
	for (i = 0; i < RTE_DIM(nonleaf_id); i++) {
		memset(&node_params, 0, sizeof(node_params));
		node_params.shaper_profile_id = 1;
		node_params.nonleaf.n_sp_priorities = 0;
		node_params.stats_mask = 1;

		ret = rte_tm_node_add(port_id, nonleaf_id[i], nonleaf_parent[i],
			0, 1, i + 1, &node_params, &error);
		if (ret != 0)
			goto tm_error;
	}

	/* leaves parented directly to 700, level 4 -- this is the level cnxk accepts for leaves */
	for (i = 0; i < N_TX_QUEUES; i++) {
		memset(&node_params, 0, sizeof(node_params));
		node_params.shaper_profile_id = 1;
		node_params.leaf.cman = RTE_TM_CMAN_TAIL_DROP;
		node_params.stats_mask = 0;

		ret = rte_tm_node_add(port_id, i, leaf_parent,
			0, 1, RTE_DIM(nonleaf_id) + 1, &node_params, &error);
		if (ret != 0)
			goto tm_error;
	}

	ret = rte_tm_hierarchy_commit(port_id, 0, &error);
	if (ret != 0)
		goto tm_error;

	RTE_LOG(INFO, APP, "Port %u: TM hierarchy committed (root=%u)\n",
		port_id, root_id);
	return 0;

tm_error:
	RTE_LOG(ERR, APP, "TM config failed on port %u: %s\n",
		port_id, error.message ? error.message : "unknown");
	return ret;
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

	// local_port_conf.rxmode.offloads |=
	// 		RTE_ETH_RX_OFFLOAD_VLAN;
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
		ret = rte_eth_tx_queue_setup(portid, i, (uint16_t)ring_conf.tx_size, rte_eth_dev_socket_id(portid), &tx_conf);

		int burst = 1;
		if (i != 0)
		 	burst = 4;
		
		tx_buffer[portid][i] = rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(burst), 0, rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid][i] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n", portid);
		
		rte_eth_tx_buffer_init(tx_buffer[portid][i], burst);

		if (ret < 0)
		       	rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%u queue=%d\n", ret, portid, i);
	}

	/* cnxk (Octeon) rte_tm tree; on iavf, PMDLink sets priorities after start */
	if (strcmp(dev_info.driver_name, "net_iavf") != 0)
		app_init_port_tm(portid);

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
	int ret;

	if (rte_eth_dev_count_avail() == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet port - bye\n");

	/* load configuration profile */
	if (app_load_cfg_profile(cfg_profile) != 0)
		rte_exit(EXIT_FAILURE, "Invalid configuration profile\n");

	/* Initialize each active flow */
	for(i = 0; i < nb_pfc; i++) {
		uint32_t socket = rte_lcore_to_socket_id(qos_conf[i].rx_core);
		struct rte_ring *ring;
		struct rte_eth_link link;
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

		memset(&link, 0, sizeof(link));
		ret = rte_eth_link_get(qos_conf[i].tx_port, &link);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_link_get: err=%d, port=%u: %s\n",
				 ret, qos_conf[i].tx_port, rte_strerror(-ret));
		if (link.link_status == 0)
			printf("Waiting for link on port %u\n", qos_conf[i].tx_port);

		while (link.link_status == 0 && retry_count--) {
			rte_delay_ms(retry_delay);
			ret = rte_eth_link_get(qos_conf[i].tx_port, &link);
			rte_exit(EXIT_FAILURE,
				 "rte_eth_link_get: err=%d, port=%u: %s\n",
				 ret, qos_conf[i].tx_port, rte_strerror(-ret));
		}

		qos_conf[i].sched_port = app_init_sched_port(qos_conf[i].tx_port, socket);

		for (int tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++)
			pstats_reset(&qos_conf[i].tc_stats[tc]);
	}

	rte_telemetry_register_cmd( "/qos/pending_stats", telemetry_pending_stats,
				    "Pending queue stats. Params: flow_id[,tc]");
	rte_telemetry_register_cmd("/qos/ctrl_stats", telemetry_ctrl_stats,
				   "Controller run telemetry (monotonic). Params: flow_id");
	rte_telemetry_register_cmd("/qos/scenario", telemetry_scenario,
				   "Static run configuration. No params");

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
