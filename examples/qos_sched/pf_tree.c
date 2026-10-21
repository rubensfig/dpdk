/* SPDX-License-Identifier: BSD-3-Clause
 *
 * PF mode for qos_sched (--pf-tree): several HQoS instances share one PF
 * port, and the NIC Tx scheduler tree decides how they share it.
 *
 *   pfc i = instance i
 *     RX: queue i of its rx port; an rte_flow rule steers the instance's
 *         destination MAC (Ixia gateway MAC, --pf-inst-mac + i) to it.
 *     MACs: with --pf-dst-mac every frame leaves with static MACs: source =
 *         the tx port's own MAC, destination = the Ixia MAC of the instance
 *         (--pf-dst-mac with byte 1 + i, the upstream device MAC of
 *         build_network_config). No frame ever carries a DUT or gateway MAC
 *         as destination, so nothing can be sent back to the DUT.
 *         Without it: MACs swapped; when rx port != tx port the source is the
 *         tx port's own MAC (else the switch sees the gateway MAC behind the
 *         tx port too: station move, dropped against a static FDB entry).
 *     TX: queues txq_base .. txq_base + PF_NQ - 1 of its tx port,
 *         txq_base = i * PF_NQ; traffic class tc goes to txq_base + tc2q[tc].
 *
 *   --pf-tree class      root - shaper - class c [SP prio c] - q(i,c) [weight 1]
 *                        priority across instances, instances share a class
 *   --pf-tree instance   root - shaper - inst i [weight 1] - q(i,c) [SP prio c]
 *                        the per-VF behaviour: instances share the port first
 *   --pf-tree default    driver's default tree, no TM configuration
 *
 * Same tree code as examples/hqos_tree, see the notes there (ice: no
 * capabilities, leaf depth detected by trial, root shaper ignored so the
 * shaper sits on the node below the root, fan-out 8 per node).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_tm.h>

#include "main.h"

#define PF_NODE_BASE 100000u	/* non-leaf TM node ids, above any queue id */
#define PF_SHAPER_ID 1

struct pf_conf pf_conf = {
	.shape = PF_TREE_OFF,
	.rate_gbps = 25.0,
	.inst_mac = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x00}},
	.levels = -1,
};

/* Default: the scheduler's TC order, TC c -> NIC class c (c = 0 highest);
 * TCs 7..12 (the lowest SP classes and best effort) share the last class.
 * The workloads use 8 classes, TC 0..7, so each has its own NIC class. */
static const uint8_t pf_default_tc2q[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE] = {
	0, 1, 2, 3, 4, 5, 6, 7, 7, 7, 7, 7, 7,
};

/* --pf-tc-map, applied in pf_init_ports() (PF mode only) */
static uint8_t pf_tc2q[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
static bool pf_tc2q_given;

static const char *const pf_shape_names[] = {
	[PF_TREE_OFF] = "off", [PF_TREE_CLASS] = "class",
	[PF_TREE_INSTANCE] = "instance", [PF_TREE_DEFAULT] = "default",
};

const char *
pf_tree_name(void)
{
	return pf_shape_names[pf_conf.shape];
}

int
pf_parse_tree(const char *s)
{
	for (unsigned int i = PF_TREE_CLASS; i < RTE_DIM(pf_shape_names); i++)
		if (strcmp(s, pf_shape_names[i]) == 0) {
			pf_conf.shape = (enum pf_tree_shape)i;
			return 0;
		}
	return -1;
}

int
pf_parse_tc_map(const char *s)
{
	uint8_t map[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	char *dup = strdup(s), *tok, *save = NULL;
	int n = 0;

	for (tok = strtok_r(dup, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		long v = strtol(tok, NULL, 0);

		if (n >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE || v < 0 || v >= PF_NQ) {
			free(dup);
			return -1;
		}
		map[n++] = (uint8_t)v;
	}
	free(dup);
	if (n != RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE)
		return -1;
	memcpy(pf_tc2q, map, sizeof(map));
	pf_tc2q_given = true;
	return 0;
}

/* ---------------------------------------------------------------- TM tree */

static bool
pf_is_ice(uint16_t port)
{
	struct rte_eth_dev_info info;

	return rte_eth_dev_info_get(port, &info) == 0 &&
		strcmp(info.driver_name, "net_ice") == 0;
}

/* ice reports no capabilities and accepts leaves only at its leaf level:
 * find it by trial under a temporary root, then delete the probe nodes. */
static int
pf_detect_levels(uint16_t port)
{
	const uint32_t base = PF_NODE_BASE + 90000;
	struct rte_tm_node_params np, lp;
	struct rte_tm_error err = {0};
	uint32_t parent = base;
	int found = -1, depth = 0;

	memset(&np, 0, sizeof(np));
	np.shaper_profile_id = RTE_TM_SHAPER_PROFILE_ID_NONE;
	np.nonleaf.n_sp_priorities = 1;
	memset(&lp, 0, sizeof(lp));
	lp.shaper_profile_id = RTE_TM_SHAPER_PROFILE_ID_NONE;
	lp.leaf.cman = RTE_TM_CMAN_TAIL_DROP;
	lp.leaf.wred.wred_profile_id = RTE_TM_WRED_PROFILE_ID_NONE;

	if (rte_tm_node_add(port, base, RTE_TM_NODE_ID_NULL, 0, 1, 0, &np, &err))
		return -1;
	for (uint32_t l = 1; l < 16; l++) {
		if (rte_tm_node_add(port, 0, parent, 0, 1, l, &lp, &err) == 0) {
			rte_tm_node_delete(port, 0, &err);
			found = (int)l + 1;
			break;
		}
		if (rte_tm_node_add(port, base + l, parent, 0, 1, l, &np, &err))
			break;
		parent = base + l;
		depth = (int)l;
	}
	for (int l = depth; l >= 0; l--)
		rte_tm_node_delete(port, base + (uint32_t)l, &err);
	return found;
}

static void
pf_tm_add(uint16_t port, bool ice, uint32_t id, uint32_t parent, uint32_t prio,
	  uint32_t weight, uint32_t level, bool leaf, uint32_t shaper,
	  uint32_t n_sp, const char *label)
{
	struct rte_tm_node_params p;
	struct rte_tm_error err = {0};
	int ret;

	memset(&p, 0, sizeof(p));
	p.shaper_profile_id = shaper;
	if (leaf) {
		p.leaf.cman = RTE_TM_CMAN_TAIL_DROP;
		p.leaf.wred.wred_profile_id = RTE_TM_WRED_PROFILE_ID_NONE;
	} else {
		p.nonleaf.wfq_weight_mode = NULL;
		/* ice accepts only 1 but still applies sibling priorities */
		p.nonleaf.n_sp_priorities = ice ? 1 : RTE_MAX(n_sp, 1u);
	}
	ret = rte_tm_node_add(port, id, parent, prio, weight, level, &p, &err);
	if (ret)
		rte_exit(EXIT_FAILURE, "PF tree port %u: node %u (%s) parent %u level %u "
			 "prio %u weight %u: %d (%s)\n", port, id, label, parent, level,
			 prio, weight, ret, err.message ? err.message : "-");
	printf("  %*s%-12s id %-6u level %u prio %u weight %u\n",
	       (int)(2 * level), "", label, id, level, prio, weight);
}

/* n_inst instances x PF_NQ classes on port; queue of (i, c) = i * PF_NQ + c */
static void
pf_tm_build(uint16_t port, uint16_t n_inst)
{
	const bool ice = pf_is_ice(port);
	const bool by_class = pf_conf.shape == PF_TREE_CLASS;
	const uint16_t n_groups = by_class ? PF_NQ : n_inst;
	const uint16_t n_per_group = by_class ? n_inst : PF_NQ;
	struct rte_tm_capabilities cap;
	struct rte_tm_error err = {0};
	uint32_t next_id = PF_NODE_BASE, root, parent;
	uint32_t shaper = RTE_TM_SHAPER_PROFILE_ID_NONE;
	int levels = pf_conf.levels, group_level, ret;

	if (levels < 0) {
		memset(&cap, 0, sizeof(cap));
		if (rte_tm_capabilities_get(port, &cap, &err) == 0)
			levels = (int)cap.n_levels_max;
		else if (ice)
			levels = pf_detect_levels(port);
		if (levels < 0)
			levels = 3;
	}
	group_level = levels - 2;
	if (group_level < 1 || (ice && pf_conf.rate_gbps > 0 && group_level < 2))
		rte_exit(EXIT_FAILURE, "PF tree port %u: %d levels are too few "
			 "(drop tm_sched_levels or set --pf-levels)\n", port, levels);
	if (ice && n_groups > 8)
		printf("WARNING: ice default topology has fan-out 8 per node "
		       "(%u groups x %u queues)\n", n_groups, n_per_group);

	if (pf_conf.rate_gbps > 0) {
		struct rte_tm_shaper_params sp;

		memset(&sp, 0, sizeof(sp));
		sp.peak.rate = (uint64_t)(pf_conf.rate_gbps * 1e9 / 8);
		if (!ice)	/* ice rejects length adjustment and bucket sizes */
			sp.pkt_length_adjust = RTE_TM_ETH_FRAMING_OVERHEAD_FCS;
		ret = rte_tm_shaper_profile_add(port, PF_SHAPER_ID, &sp, &err);
		if (ret)
			rte_exit(EXIT_FAILURE, "PF tree port %u: shaper: %d (%s)\n", port,
				 ret, err.message ? err.message : "-");
		shaper = PF_SHAPER_ID;
	}

	printf("PF tree port %u: %s-major, %u instances x %u queues, %d levels, "
	       "shaper %.2f Gb/s%s\n", port, by_class ? "class" : "instance",
	       n_inst, PF_NQ, levels, pf_conf.rate_gbps,
	       ice ? " (ice: on the node below the root, L2 bytes)" : "");

	/* ice maps the root onto an existing HW node and programs only the
	 * nodes below it, so the shaper goes on the first node under the root */
	root = next_id++;
	pf_tm_add(port, ice, root, RTE_TM_NODE_ID_NULL, 0, 1, 0, false,
		  ice ? RTE_TM_SHAPER_PROFILE_ID_NONE : shaper,
		  group_level == 1 && by_class ? PF_NQ : 1, "root");
	parent = root;
	for (int l = 1; l < group_level; l++) {
		uint32_t id = next_id++;
		bool sh = ice && l == 1;

		pf_tm_add(port, ice, id, parent, 0, 1, (uint32_t)l, false,
			  sh ? shaper : RTE_TM_SHAPER_PROFILE_ID_NONE,
			  l == group_level - 1 && by_class ? PF_NQ : 1,
			  sh && shaper != RTE_TM_SHAPER_PROFILE_ID_NONE ? "pad+shaper" : "pad");
		parent = id;
	}

	for (uint16_t gi = 0; gi < n_groups; gi++) {
		uint32_t gid = next_id++;
		char label[32];

		snprintf(label, sizeof(label), "%s%u", by_class ? "class" : "inst", gi);
		pf_tm_add(port, ice, gid, parent, by_class ? gi : 0, 1,
			  (uint32_t)group_level, false, RTE_TM_SHAPER_PROFILE_ID_NONE,
			  by_class ? 1 : PF_NQ, label);

		for (uint16_t k = 0; k < n_per_group; k++) {
			uint16_t inst = by_class ? k : gi;
			uint16_t cls = by_class ? gi : k;
			uint32_t qid = (uint32_t)inst * PF_NQ + cls;

			snprintf(label, sizeof(label), "q%u(i%u,c%u)", qid, inst, cls);
			pf_tm_add(port, ice, qid, gid, by_class ? 0 : cls, 1,
				  (uint32_t)group_level + 1, true,
				  RTE_TM_SHAPER_PROFILE_ID_NONE, 0, label);
		}
	}

	ret = rte_tm_hierarchy_commit(port, 1, &err);
	if (ret)
		rte_exit(EXIT_FAILURE, "PF tree port %u: commit: %d (%s)\n", port, ret,
			 err.message ? err.message : "-");
	printf("PF tree port %u: committed\n", port);
}

/* ---------------------------------------------------------------- RX steering */

static void
pf_flow_rule(uint16_t port, uint16_t queue, const struct rte_ether_addr *mac)
{
	struct rte_flow_attr attr = { .ingress = 1 };
	struct rte_flow_item_eth spec, mask;
	struct rte_flow_item pattern[2];
	struct rte_flow_action_queue q = { .index = queue };
	struct rte_flow_action action[2];
	struct rte_flow_error err;
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	memset(&spec, 0, sizeof(spec));
	memset(&mask, 0, sizeof(mask));
	rte_ether_addr_copy(mac, &spec.hdr.dst_addr);
	memset(&mask.hdr.dst_addr, 0xff, sizeof(mask.hdr.dst_addr));

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &spec;
	pattern[0].mask = &mask;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &q;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	rte_ether_format_addr(buf, sizeof(buf), mac);
	memset(&err, 0, sizeof(err));
	if (rte_flow_create(port, &attr, pattern, action, &err) == NULL)
		rte_exit(EXIT_FAILURE, "PF port %u: rte_flow dst %s -> rxq %u failed: %s "
			 "(rules left in the NIC by a killed instance? unbind/rebind the PF "
			 "or reload ice to reset it)\n",
			 port, buf, queue, err.message ? err.message : "-");
	printf("PF port %u: dst %s -> rx queue %u\n", port, buf, queue);
}

/* ---------------------------------------------------------------- ports */

static void
pf_init_port(uint16_t port)
{
	struct rte_eth_conf conf = { .txmode = { .mq_mode = RTE_ETH_MQ_TX_NONE } };
	struct rte_eth_dev_info info;
	struct rte_eth_txconf txc;
	struct rte_eth_rxconf rxc;
	struct rte_eth_link link;
	uint16_t rxd = (uint16_t)ring_conf.rx_size, txd = (uint16_t)ring_conf.tx_size;
	uint16_t n_rx = 0, n_tx_inst = 0, nb_rxq, nb_txq;
	struct rte_mempool *mp0 = NULL;
	int ret;

	/* instances on this port: RX queue / TX queue block by position */
	for (uint32_t i = 0; i < nb_pfc; i++) {
		if (qos_conf[i].rx_port == port) {
			qos_conf[i].rx_queue = n_rx++;
			if (mp0 == NULL)
				mp0 = qos_conf[i].mbuf_pool;
		}
		if (qos_conf[i].tx_port == port)
			qos_conf[i].txq_base = (uint16_t)(n_tx_inst++ * PF_NQ);
	}
	if (mp0 == NULL)
		mp0 = qos_conf[0].mbuf_pool;
	nb_rxq = RTE_MAX(n_rx, (uint16_t)1);
	nb_txq = RTE_MAX((uint16_t)(n_tx_inst * PF_NQ), (uint16_t)1);
	if (nb_txq > MAX_TXQ_PER_PORT)
		rte_exit(EXIT_FAILURE, "PF port %u: %u TX queues > %u\n", port, nb_txq,
			 MAX_TXQ_PER_PORT);

	ret = rte_eth_dev_info_get(port, &info);
	if (ret)
		rte_exit(EXIT_FAILURE, "PF port %u: dev_info: %d\n", port, ret);
	if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
	ret = rte_eth_dev_configure(port, nb_rxq, nb_txq, &conf);
	if (ret)
		rte_exit(EXIT_FAILURE, "PF port %u: configure %u rxq / %u txq: %d\n",
			 port, nb_rxq, nb_txq, ret);
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &rxd, &txd);
	if (ret)
		rte_exit(EXIT_FAILURE, "PF port %u: adjust desc: %d\n", port, ret);
	ring_conf.rx_size = rxd;
	ring_conf.tx_size = txd;

	memset(&rxc, 0, sizeof(rxc));
	rxc.rx_thresh.pthresh = rx_thresh.pthresh;
	rxc.rx_thresh.hthresh = rx_thresh.hthresh;
	rxc.rx_thresh.wthresh = rx_thresh.wthresh;
	rxc.rx_free_thresh = 32;
	if (n_rx == 0) {	/* tx-only port: one unused RX queue */
		ret = rte_eth_rx_queue_setup(port, 0, rxd, rte_eth_dev_socket_id(port),
					     &rxc, mp0);
		if (ret)
			rte_exit(EXIT_FAILURE, "PF port %u: rxq 0: %d\n", port, ret);
	}
	for (uint32_t i = 0; i < nb_pfc; i++) {
		if (qos_conf[i].rx_port != port)
			continue;
		ret = rte_eth_rx_queue_setup(port, qos_conf[i].rx_queue, rxd,
					     rte_eth_dev_socket_id(port), &rxc,
					     qos_conf[i].mbuf_pool);
		if (ret)
			rte_exit(EXIT_FAILURE, "PF port %u: rxq %u: %d\n", port,
				 qos_conf[i].rx_queue, ret);
	}

	memset(&txc, 0, sizeof(txc));
	txc.tx_thresh.pthresh = tx_thresh.pthresh;
	txc.tx_thresh.hthresh = tx_thresh.hthresh;
	txc.tx_thresh.wthresh = tx_thresh.wthresh;
	txc.offloads = conf.txmode.offloads;
	for (uint16_t q = 0; q < nb_txq; q++) {
		ret = rte_eth_tx_queue_setup(port, q, txd, rte_eth_dev_socket_id(port), &txc);
		if (ret)
			rte_exit(EXIT_FAILURE, "PF port %u: txq %u: %d\n", port, q, ret);
		/* tx and prioprop threads use tx buffers (burst 1 on the HP queue) */
		uint16_t burst = q % PF_NQ == 0 ? 1 : 4;

		tx_buffer[port][q] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(burst), 0, rte_eth_dev_socket_id(port));
		if (tx_buffer[port][q] == NULL)
			rte_exit(EXIT_FAILURE, "PF port %u: tx buffer %u\n", port, q);
		rte_eth_tx_buffer_init(tx_buffer[port][q], burst);
	}

	if (n_tx_inst && pf_conf.shape != PF_TREE_DEFAULT)
		pf_tm_build(port, n_tx_inst);
	else if (n_tx_inst)
		printf("PF port %u: driver default Tx tree (--pf-tree default)\n", port);

	ret = rte_eth_dev_start(port);
	if (ret)
		rte_exit(EXIT_FAILURE, "PF port %u: start: %d\n", port, ret);
	/* instance MACs are not the port's own */
	ret = rte_eth_promiscuous_enable(port);
	if (ret)
		rte_exit(EXIT_FAILURE, "PF port %u: promiscuous: %d\n", port, ret);

	/* start from no rules (the flows of this process; see pf_cleanup()) */
	{
		struct rte_flow_error ferr;

		rte_flow_flush(port, &ferr);
	}
	for (uint32_t i = 0; i < nb_pfc; i++) {
		struct rte_ether_addr mac = pf_conf.inst_mac;

		if (qos_conf[i].rx_port != port)
			continue;
		mac.addr_bytes[5] = (uint8_t)(mac.addr_bytes[5] + i);
		pf_flow_rule(port, qos_conf[i].rx_queue, &mac);
	}

	/* rte_sched takes its port rate from the link speed: wait for it */
	for (int t = 0; t < 100; t++) {
		if (rte_eth_link_get_nowait(port, &link) == 0 && link.link_status &&
		    link.link_speed != RTE_ETH_SPEED_NUM_UNKNOWN && link.link_speed)
			break;
		rte_delay_ms(100);
	}
	if (!link.link_status || !link.link_speed ||
	    link.link_speed == RTE_ETH_SPEED_NUM_UNKNOWN)
		rte_exit(EXIT_FAILURE, "PF port %u: no link after 10 s\n", port);
	printf("PF port %u (%s): %u rxq, %u txq, link %u Mb/s\n", port, info.driver_name,
	       nb_rxq, nb_txq, link.link_speed);
}

/* Remove the PF flow rules. Called on SIGINT/SIGTERM:
 * without it a killed instance leaves its rte_flow rules in the NIC, and the
 * next instance cannot create the same rules. */
void
pf_cleanup(void)
{
	uint64_t done = 0;

	if (pf_conf.shape == PF_TREE_OFF)
		return;
	for (uint32_t i = 0; i < nb_pfc; i++) {
		uint16_t ports[2] = { qos_conf[i].rx_port, qos_conf[i].tx_port };

		for (int k = 0; k < 2; k++) {
			struct rte_flow_error ferr;

			if (done & (1ull << ports[k]))
				continue;
			done |= 1ull << ports[k];
			/* only the rules: the workers still transmit on the ports */
			rte_flow_flush(ports[k], &ferr);
		}
	}
	printf("PF mode: flow rules removed\n");
}

void
pf_init_ports(void)
{
	uint64_t done = 0;

	for (int t = 0; t < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; t++)
		app_tc2q[t] = pf_tc2q_given ? pf_tc2q[t] : pf_default_tc2q[t];

	printf("PF mode: tree %s, %u instances, TC->queue map", pf_tree_name(), nb_pfc);
	for (int t = 0; t < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; t++)
		printf("%c%u", t ? ',' : ' ', app_tc2q[t]);
	printf("\n");

	for (uint32_t i = 0; i < nb_pfc; i++) {
		uint16_t ports[2] = { qos_conf[i].rx_port, qos_conf[i].tx_port };

		for (int k = 0; k < 2; k++) {
			if (done & (1ull << ports[k]))
				continue;
			pf_init_port(ports[k]);
			done |= 1ull << ports[k];
		}
	}
	for (uint32_t i = 0; i < nb_pfc; i++) {
		struct thread_conf *rx = &qos_conf[i].rx_thread;
		char s[RTE_ETHER_ADDR_FMT_SIZE], d[RTE_ETHER_ADDR_FMT_SIZE];

		rte_eth_macaddr_get(qos_conf[i].tx_port, &rx->src_mac);
		rte_ether_format_addr(s, sizeof(s), &rx->src_mac);
		if (pf_conf.set_dst) {
			rx->dst_mac = pf_conf.dst_mac;
			rx->dst_mac.addr_bytes[1] = (uint8_t)(rx->dst_mac.addr_bytes[1] + i);
			rx->mac_rewrite = 2;
			rte_ether_format_addr(d, sizeof(d), &rx->dst_mac);
			printf("PF instance %u: frames leave with src %s dst %s\n", i, s, d);
		} else if (qos_conf[i].rx_port != qos_conf[i].tx_port) {
			rx->mac_rewrite = 1;
			printf("PF instance %u: frames leave with src %s (dst: swapped)\n", i, s);
		}
	}
	for (uint32_t i = 0; i < nb_pfc; i++)
		printf("PF instance %u: rx port %u queue %u, tx port %u queues %u..%u\n", i,
		       qos_conf[i].rx_port, qos_conf[i].rx_queue, qos_conf[i].tx_port,
		       qos_conf[i].txq_base, qos_conf[i].txq_base + PF_NQ - 1);
}
