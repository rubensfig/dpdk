/* SPDX-License-Identifier: BSD-3-Clause
 *
 * hqos_tree: minimal PF forwarder to test NIC Tx scheduler trees.
 *
 * Question it answers: with N instances x C classes sharing one PF Tx port,
 * how does the NIC split a congested port between instances and classes
 * for two tree shapes?
 *
 *   --shape instance   (per-VF behaviour)    --shape class   (global priority)
 *
 *   root (shaper)                             root (shaper)
 *    +- inst 0  [weight w0]                    +- class 0  [priority 0 = highest]
 *    |   +- q(0,c) [priority c]                |   +- q(i,0) [weight w_i]
 *    +- inst 1  [weight w1]                    +- class 1  [priority 1]
 *        +- q(1,c) [priority c]                    +- q(i,1) [weight w_i]
 *
 * Tx queue of (instance i, class c) is always q = i * C + c, so both shapes
 * see identical traffic; only the tree differs. No software scheduler and no
 * backpressure: packets the NIC ring does not accept are dropped and counted,
 * so the measured split is the NIC's alone.
 *
 * Classification:
 *   instance = last byte of the destination MAC % N  (Ixia gateway MAC
 *              00:11:22:33:44:<idx>)
 *   class    = raw IPv4 ToS byte through --tos-map (default matches the
 *              Ixia priorities of the allthing workloads), unknown -> C-1
 *
 * Usage (E810 PF, two ports, 2 instances x 2 classes, class-major tree):
 *   dpdk-hqos_tree -l 2 -a 0000:4d:00.0 -a 0000:4d:00.1,tm_sched_levels=3 -- \
 *       --rx-port 0 --tx-port 1 --instances 2 --classes 2 --shape class \
 *       --rate-gbps 25
 *   --probe       print rte_tm capabilities of the Tx port and exit
 *   --no-tm       leave the driver's default tree (baseline)
 *
 * ice notes (24.11): no capabilities_get, so the depth comes from --levels
 * (default 3 = root / queue group / queue, use devarg tm_sched_levels=3);
 * fan-out is 8 per node on the default topology, so <= 8 groups and <= 8
 * leaves per group. Non-leaf nodes must declare n_sp_priorities = 1; the
 * driver still applies node priorities between siblings.
 * cnxk notes: leaves (SQs) must have priority 0, so use --leaf-chain 1 to put
 * the priority/weight on a parent of each leaf; check --probe first.
 */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_tm.h>

#define MAX_INST     16
#define MAX_CLASS    8
#define MAX_TXQ      (MAX_INST * MAX_CLASS)
#define BURST        64
#define NODE_BASE    100000u  /* non-leaf node ids, above any queue id */
#define SHAPER_ID    1

enum shape { SHAPE_CLASS, SHAPE_INSTANCE };

static struct {
	uint16_t rx_port, tx_port;
	uint16_t n_inst, n_class;
	enum shape shape;
	double rate_gbps;           /* 0: no root shaper */
	uint32_t weight[MAX_INST];
	int levels;                 /* -1: from capabilities, else 3 */
	int leaf_chain;
	uint16_t rxd, txd;
	bool probe, no_tm, csv;
	bool set_dst;
	struct rte_ether_addr dst_mac;  /* --dst-mac: rewrite destination */
	struct rte_ether_addr tx_mac;   /* source MAC written on every frame */
	unsigned int stats_ms;
	bool is_ice;
} g = {
	.rx_port = 0, .tx_port = 1, .n_inst = 2, .n_class = 8,
	.shape = SHAPE_CLASS, .rate_gbps = 25.0, .levels = -1,
	.rxd = 4096, .txd = 1024, .stats_ms = 1000,
};

struct qstat {
	uint64_t tx_pkts, tx_bytes, drop_pkts, drop_bytes;
};

static volatile bool force_quit;
static uint8_t tos2class[256];
static struct qstat st[MAX_TXQ], st_prev[MAX_TXQ];
static struct rte_mbuf *qbuf[MAX_TXQ][BURST];
static uint32_t qbytes[MAX_TXQ][BURST];
static uint16_t qlen[MAX_TXQ];
static uint16_t active[MAX_TXQ];
static uint16_t n_active;
static uint64_t rx_pkts, rx_pkts_prev;
static uint64_t looped, looped_prev;  /* frames we sent that came back in */

static void
on_signal(int sig)
{
	(void)sig;
	force_quit = true;
}

/* ---------------------------------------------------------------- args */

/* default: raw ToS bytes the allthing Ixia workloads send */
static const struct { uint8_t tos; uint8_t cls; } default_tos_map[] = {
	{0x00, 0}, {0x04, 1}, {0x08, 2}, {0x12, 3},
	{0x16, 4}, {0x20, 5}, {0x24, 6}, {0x28, 7},
};

static void
set_default_tos_map(void)
{
	memset(tos2class, g.n_class - 1, sizeof(tos2class));
	for (unsigned int i = 0; i < RTE_DIM(default_tos_map); i++)
		tos2class[default_tos_map[i].tos] =
			RTE_MIN(default_tos_map[i].cls, g.n_class - 1);
}

/* "0x00:0,0x04:1,..." */
static int
parse_tos_map(const char *s)
{
	char *dup = strdup(s), *tok, *save = NULL;

	memset(tos2class, g.n_class - 1, sizeof(tos2class));
	for (tok = strtok_r(dup, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		char *colon = strchr(tok, ':');
		unsigned long tos, cls;

		if (colon == NULL)
			goto bad;
		*colon = '\0';
		tos = strtoul(tok, NULL, 0);
		cls = strtoul(colon + 1, NULL, 0);
		if (tos > 255 || cls >= g.n_class)
			goto bad;
		tos2class[tos] = (uint8_t)cls;
	}
	free(dup);
	return 0;
bad:
	free(dup);
	return -1;
}

/* "1,3" -> instance weights */
static int
parse_weights(const char *s)
{
	char *dup = strdup(s), *tok, *save = NULL;
	unsigned int i = 0;

	for (tok = strtok_r(dup, ",", &save); tok && i < MAX_INST;
	     tok = strtok_r(NULL, ",", &save))
		g.weight[i++] = (uint32_t)strtoul(tok, NULL, 0);
	free(dup);
	return i ? 0 : -1;
}

static void
usage(const char *prog)
{
	printf("%s [EAL options] -- [options]\n"
	       "  --rx-port P        ingress port (default 0)\n"
	       "  --tx-port P        egress port with the tree (default 1, may equal rx)\n"
	       "  --instances N      instances, <= %d (default 2)\n"
	       "  --classes C        classes, <= %d (default 8)\n"
	       "  --shape class|instance   tree shape (default class)\n"
	       "  --rate-gbps R      root shaper, 0 = none (default 25)\n"
	       "  --weights w0,w1,.. instance weights (default all 1)\n"
	       "  --levels L         tree depth incl. root and leaves (default: caps, else 3)\n"
	       "  --leaf-chain K     pass-through parents per leaf (cnxk: 1)\n"
	       "  --tos-map t:c,..   raw ToS byte -> class (default Ixia map)\n"
	       "  --rxd N --txd N    ring sizes (default 4096 / 1024)\n"
	       "  --stats-ms MS      stats interval (default 1000)\n"
	       "  --csv              also print CSV lines\n"
	       "  --dst-mac MAC      rewrite the destination MAC (default: keep)\n"
	       "  --probe            print TM capabilities and exit\n"
	       "  --no-tm            keep the driver's default tree\n",
	       prog, MAX_INST, MAX_CLASS);
}

static int
parse_args(int argc, char **argv)
{
	static const struct option opts[] = {
		{"rx-port", 1, 0, 'r'}, {"tx-port", 1, 0, 't'},
		{"instances", 1, 0, 'n'}, {"classes", 1, 0, 'c'},
		{"shape", 1, 0, 's'}, {"rate-gbps", 1, 0, 'R'},
		{"weights", 1, 0, 'w'}, {"levels", 1, 0, 'L'},
		{"leaf-chain", 1, 0, 'K'}, {"tos-map", 1, 0, 'm'},
		{"rxd", 1, 0, 'x'}, {"txd", 1, 0, 'y'},
		{"stats-ms", 1, 0, 'S'}, {"csv", 0, 0, 'C'},
		{"probe", 0, 0, 'p'}, {"no-tm", 0, 0, 'N'},
		{"dst-mac", 1, 0, 'D'},
		{"help", 0, 0, 'h'}, {0, 0, 0, 0},
	};
	const char *tos_map = NULL;
	int o;

	for (unsigned int i = 0; i < MAX_INST; i++)
		g.weight[i] = 1;

	while ((o = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
		switch (o) {
		case 'r': g.rx_port = (uint16_t)atoi(optarg); break;
		case 't': g.tx_port = (uint16_t)atoi(optarg); break;
		case 'n': g.n_inst = (uint16_t)atoi(optarg); break;
		case 'c': g.n_class = (uint16_t)atoi(optarg); break;
		case 's':
			if (!strcmp(optarg, "class"))
				g.shape = SHAPE_CLASS;
			else if (!strcmp(optarg, "instance"))
				g.shape = SHAPE_INSTANCE;
			else
				return -1;
			break;
		case 'R': g.rate_gbps = atof(optarg); break;
		case 'w': if (parse_weights(optarg)) return -1; break;
		case 'L': g.levels = atoi(optarg); break;
		case 'K': g.leaf_chain = atoi(optarg); break;
		case 'm': tos_map = optarg; break;
		case 'x': g.rxd = (uint16_t)atoi(optarg); break;
		case 'y': g.txd = (uint16_t)atoi(optarg); break;
		case 'S': g.stats_ms = (unsigned int)atoi(optarg); break;
		case 'C': g.csv = true; break;
		case 'p': g.probe = true; break;
		case 'N': g.no_tm = true; break;
		case 'D':
			if (rte_ether_unformat_addr(optarg, &g.dst_mac))
				return -1;
			g.set_dst = true;
			break;
		default: return -1;
		}
	}
	if (g.n_inst < 1 || g.n_inst > MAX_INST || g.n_class < 1 || g.n_class > MAX_CLASS)
		return -1;
	if (tos_map) {
		if (parse_tos_map(tos_map))
			return -1;
	} else {
		set_default_tos_map();
	}
	return 0;
}

/* ---------------------------------------------------------------- ports */

static void
port_init(uint16_t port, uint16_t nb_rxq, uint16_t nb_txq, struct rte_mempool *mp)
{
	struct rte_eth_conf conf = {0};
	struct rte_eth_dev_info info;
	struct rte_eth_txconf txc;
	uint16_t rxd = g.rxd, txd = g.txd;
	int ret;

	ret = rte_eth_dev_info_get(port, &info);
	if (ret)
		rte_exit(EXIT_FAILURE, "port %u: dev_info_get: %d\n", port, ret);
	if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
	if (nb_txq > info.max_tx_queues)
		rte_exit(EXIT_FAILURE, "port %u: %u Tx queues > max %u\n",
			 port, nb_txq, info.max_tx_queues);

	ret = rte_eth_dev_configure(port, nb_rxq, nb_txq, &conf);
	if (ret)
		rte_exit(EXIT_FAILURE, "port %u: configure: %d\n", port, ret);
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &rxd, &txd);
	if (ret)
		rte_exit(EXIT_FAILURE, "port %u: adjust desc: %d\n", port, ret);

	for (uint16_t q = 0; q < nb_rxq; q++) {
		ret = rte_eth_rx_queue_setup(port, q, rxd, rte_eth_dev_socket_id(port),
					     NULL, mp);
		if (ret)
			rte_exit(EXIT_FAILURE, "port %u: rxq %u: %d\n", port, q, ret);
	}
	txc = info.default_txconf;
	txc.offloads = conf.txmode.offloads;
	for (uint16_t q = 0; q < nb_txq; q++) {
		ret = rte_eth_tx_queue_setup(port, q, txd, rte_eth_dev_socket_id(port), &txc);
		if (ret)
			rte_exit(EXIT_FAILURE, "port %u: txq %u: %d\n", port, q, ret);
	}
	printf("port %u (%s): %u rxq x %u desc, %u txq x %u desc\n",
	       port, info.driver_name, nb_rxq, rxd, nb_txq, txd);
}

static void
port_start(uint16_t port)
{
	struct rte_eth_link link;
	int ret = rte_eth_dev_start(port);

	if (ret)
		rte_exit(EXIT_FAILURE, "port %u: start: %d\n", port, ret);
	rte_eth_promiscuous_enable(port);
	rte_eth_link_get(port, &link);
	printf("port %u: link %s, %u Mb/s\n", port,
	       link.link_status ? "up" : "down", link.link_speed);
}

/* ---------------------------------------------------------------- TM */

static int
probe_caps(uint16_t port, bool verbose)
{
	struct rte_tm_capabilities cap;
	struct rte_tm_error err = {0};
	int ret;

	memset(&cap, 0, sizeof(cap));
	ret = rte_tm_capabilities_get(port, &cap, &err);
	if (ret) {
		if (verbose)
			printf("TM capabilities: not reported (%d, %s)%s\n", ret,
			       err.message ? err.message : "-",
			       g.is_ice ? " - ice: depth = devarg tm_sched_levels, "
					  "fan-out 8 per node on the default topology" : "");
		return -1;
	}
	if (!verbose)
		return (int)cap.n_levels_max;

	printf("TM capabilities, port %u:\n"
	       "  nodes max %u, levels max %u\n"
	       "  shapers max %u (private %u), rate %" PRIu64 "..%" PRIu64 " B/s,"
	       " pkt_length_adjust %d..%d\n"
	       "  children max %u, SP priorities max %u,"
	       " WFQ children/group max %u, WFQ groups max %u, WFQ weight max %u\n",
	       port, cap.n_nodes_max, cap.n_levels_max,
	       cap.shaper_n_max, cap.shaper_private_n_max,
	       cap.shaper_private_rate_min, cap.shaper_private_rate_max,
	       cap.shaper_pkt_length_adjust_min, cap.shaper_pkt_length_adjust_max,
	       cap.sched_n_children_max, cap.sched_sp_n_priorities_max,
	       cap.sched_wfq_n_children_per_group_max, cap.sched_wfq_n_groups_max,
	       cap.sched_wfq_weight_max);

	for (uint32_t l = 0; l < cap.n_levels_max; l++) {
		struct rte_tm_level_capabilities lc;

		memset(&lc, 0, sizeof(lc));
		if (rte_tm_level_capabilities_get(port, l, &lc, &err)) {
			printf("  level %u: query failed (%s)\n", l,
			       err.message ? err.message : "-");
			continue;
		}
		if (lc.n_nodes_leaf_max && !lc.n_nodes_nonleaf_max) {
			printf("  level %u: leaves max %u, private shaper %d\n",
			       l, lc.n_nodes_leaf_max, lc.leaf.shaper_private_supported);
		} else {
			printf("  level %u: nodes max %u (non-leaf %u, leaf %u),"
			       " children max %u, SP prio max %u,"
			       " WFQ groups max %u, WFQ children/group max %u,"
			       " weight max %u, private shaper %d\n",
			       l, lc.n_nodes_max, lc.n_nodes_nonleaf_max, lc.n_nodes_leaf_max,
			       lc.nonleaf.sched_n_children_max,
			       lc.nonleaf.sched_sp_n_priorities_max,
			       lc.nonleaf.sched_wfq_n_groups_max,
			       lc.nonleaf.sched_wfq_n_children_per_group_max,
			       lc.nonleaf.sched_wfq_weight_max,
			       lc.nonleaf.shaper_private_supported);
		}
	}
	return (int)cap.n_levels_max;
}

static void
tm_add(uint32_t id, uint32_t parent, uint32_t prio, uint32_t weight,
       uint32_t level, bool leaf, uint32_t shaper, uint32_t n_sp, const char *label)
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
		p.nonleaf.n_sp_priorities = g.is_ice ? 1 : RTE_MAX(n_sp, 1u);
	}

	ret = rte_tm_node_add(g.tx_port, id, parent, prio, weight, level, &p, &err);
	if (ret)
		rte_exit(EXIT_FAILURE,
			 "tm node_add id %u parent %u level %u prio %u weight %u: %d (%s, type %d)\n",
			 id, parent, level, prio, weight, ret,
			 err.message ? err.message : "-", err.type);
	printf("  %*s%-10s id %-6u level %u prio %u weight %u\n",
	       (int)(2 * level), "", label, id, level, prio, weight);
}

/* ice reports no capabilities and only accepts leaves at its leaf level
 * (num_tx_sched_layers - hidden layers - 1, set by devarg tm_sched_levels).
 * Find it by trial: grow a pass-through chain under a temporary root and try
 * to attach leaf 0 at each level. Everything is deleted again afterwards. */
static int
detect_levels(void)
{
	const uint32_t base = NODE_BASE + 90000;
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

	if (rte_tm_node_add(g.tx_port, base, RTE_TM_NODE_ID_NULL, 0, 1, 0, &np, &err))
		return -1;
	for (uint32_t l = 1; l < 16; l++) {
		if (rte_tm_node_add(g.tx_port, 0, parent, 0, 1, l, &lp, &err) == 0) {
			rte_tm_node_delete(g.tx_port, 0, &err);
			found = (int)l + 1;
			break;
		}
		if (rte_tm_node_add(g.tx_port, base + l, parent, 0, 1, l, &np, &err))
			break;
		parent = base + l;
		depth = (int)l;
	}
	for (int l = depth; l >= 0; l--)
		rte_tm_node_delete(g.tx_port, base + (uint32_t)l, &err);
	return found;
}

/* Builds root -> pads -> groups -> [leaf chain] -> leaves.
 * groups = classes (class-major) or instances (instance-major). */
static void
tm_build(void)
{
	struct rte_tm_error err = {0};
	uint32_t next_id = NODE_BASE;
	uint32_t root, parent, shaper = RTE_TM_SHAPER_PROFILE_ID_NONE;
	int levels = g.levels;
	int group_level;
	uint16_t n_groups = g.shape == SHAPE_CLASS ? g.n_class : g.n_inst;
	uint16_t n_per_group = g.shape == SHAPE_CLASS ? g.n_inst : g.n_class;
	int ret;

	if (levels < 0) {
		levels = probe_caps(g.tx_port, false);
		if (levels < 0 && g.is_ice) {
			levels = detect_levels();
			if (levels > 0)
				printf("ice: detected %d usable TM levels (leaf at level %d)%s\n",
				       levels, levels - 1,
				       levels > 3 ? "; devarg tm_sched_levels=3 gives the "
						    "flat tree" : "");
		}
		if (levels < 0)
			levels = 3;
	}
	group_level = levels - 2 - g.leaf_chain;
	if (group_level < 1)
		rte_exit(EXIT_FAILURE, "levels %d too few for leaf-chain %d\n",
			 levels, g.leaf_chain);
	if (g.is_ice && (n_groups > 8 || n_per_group > 8))
		printf("WARNING: ice default topology has fan-out 8 per node "
		       "(%u groups x %u leaves)\n", n_groups, n_per_group);

	if (g.rate_gbps > 0) {
		struct rte_tm_shaper_params sp;

		memset(&sp, 0, sizeof(sp));
		sp.peak.rate = (uint64_t)(g.rate_gbps * 1e9 / 8); /* bytes/s */
		if (g.is_ice && sp.peak.rate > UINT32_MAX)  /* ice keeps it as uint32_t */
			rte_exit(EXIT_FAILURE, "ice: shaper rate above %.1f Gb/s overflows\n",
				 (double)UINT32_MAX * 8 / 1e9);
		if (!g.is_ice)  /* ice rejects length adjustment and bucket sizes */
			sp.pkt_length_adjust = RTE_TM_ETH_FRAMING_OVERHEAD_FCS;
		ret = rte_tm_shaper_profile_add(g.tx_port, SHAPER_ID, &sp, &err);
		if (ret)
			rte_exit(EXIT_FAILURE, "shaper_profile_add: %d (%s)\n", ret,
				 err.message ? err.message : "-");
		shaper = SHAPER_ID;
	}

	printf("TM tree on port %u: %s-major, %u instances x %u classes, "
	       "%d levels, group level %d, leaf chain %d, root rate %.2f Gb/s%s\n",
	       g.tx_port, g.shape == SHAPE_CLASS ? "class" : "instance",
	       g.n_inst, g.n_class, levels, group_level, g.leaf_chain, g.rate_gbps,
	       g.is_ice ? " (ice: L2 bytes, no framing overhead)" : "");

	/* root and pass-through pads down to the level above the groups.
	 * The node whose children are the groups needs n_class SP levels
	 * when groups are classes. */
	/* ice maps the root onto an existing HW node and only programs the nodes
	 * below it at commit, so a root shaper is silently ignored there: put the
	 * port shaper on the first node below the root instead. */
	if (g.is_ice && shaper != RTE_TM_SHAPER_PROFILE_ID_NONE && group_level < 2)
		rte_exit(EXIT_FAILURE, "ice: the shaper needs a node below the root; "
			 "use more levels (drop tm_sched_levels or set --levels >= %d)\n",
			 4 + g.leaf_chain);
	root = next_id++;
	tm_add(root, RTE_TM_NODE_ID_NULL, 0, 1, 0, false,
	       g.is_ice ? RTE_TM_SHAPER_PROFILE_ID_NONE : shaper,
	       group_level == 1 && g.shape == SHAPE_CLASS ? g.n_class : 1, "root");
	parent = root;
	for (int l = 1; l < group_level; l++) {
		uint32_t id = next_id++;

		tm_add(id, parent, 0, 1, (uint32_t)l, false,
		       g.is_ice && l == 1 ? shaper : RTE_TM_SHAPER_PROFILE_ID_NONE,
		       l == group_level - 1 && g.shape == SHAPE_CLASS ? g.n_class : 1,
		       g.is_ice && l == 1 && shaper != RTE_TM_SHAPER_PROFILE_ID_NONE ?
		       "pad+shaper" : "pad");
		parent = id;
	}

	for (uint16_t gi = 0; gi < n_groups; gi++) {
		uint32_t gid = next_id++;
		char label[32];
		/* class-major: group = class gi, strict priority gi.
		 * instance-major: group = instance gi, priority 0, its weight. */
		uint32_t gprio = g.shape == SHAPE_CLASS ? gi : 0;
		uint32_t gweight = g.shape == SHAPE_CLASS ? 1 : g.weight[gi];

		snprintf(label, sizeof(label), "%s%u",
			 g.shape == SHAPE_CLASS ? "class" : "inst", gi);
		tm_add(gid, parent, gprio, gweight, (uint32_t)group_level, false,
		       RTE_TM_SHAPER_PROFILE_ID_NONE,
		       g.shape == SHAPE_INSTANCE ? g.n_class : 1, label);

		for (uint16_t k = 0; k < n_per_group; k++) {
			uint16_t inst = g.shape == SHAPE_CLASS ? k : gi;
			uint16_t cls = g.shape == SHAPE_CLASS ? gi : k;
			uint32_t qid = (uint32_t)inst * g.n_class + cls;
			/* class-major: instances share a class by weight.
			 * instance-major: classes inside an instance by priority. */
			uint32_t prio = g.shape == SHAPE_CLASS ? 0 : cls;
			uint32_t weight = g.shape == SHAPE_CLASS ? g.weight[inst] : 1;
			uint32_t p = gid;
			int lvl = group_level + 1;

			for (int c = 0; c < g.leaf_chain; c++, lvl++) {
				uint32_t id = next_id++;
				bool top = c == 0;

				snprintf(label, sizeof(label), "chain q%u", qid);
				tm_add(id, p, top ? prio : 0, top ? weight : 1, (uint32_t)lvl,
				       false, RTE_TM_SHAPER_PROFILE_ID_NONE, 1, label);
				p = id;
			}
			snprintf(label, sizeof(label), "q%u(i%u,c%u)", qid, inst, cls);
			tm_add(qid, p, g.leaf_chain ? 0 : prio, g.leaf_chain ? 1 : weight,
			       (uint32_t)lvl, true, RTE_TM_SHAPER_PROFILE_ID_NONE, 0, label);
		}
	}

	ret = rte_tm_hierarchy_commit(g.tx_port, 1, &err);
	if (ret)
		rte_exit(EXIT_FAILURE, "hierarchy_commit: %d (%s, type %d)\n", ret,
			 err.message ? err.message : "-", err.type);
	printf("TM hierarchy committed\n");
}

/* ---------------------------------------------------------------- data path */

static inline void
classify(struct rte_mbuf *m, uint16_t *inst, uint16_t *cls)
{
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	uint16_t et = eth->ether_type;
	uint32_t off = sizeof(*eth);

	*inst = eth->dst_addr.addr_bytes[5] % g.n_inst;
	*cls = g.n_class - 1;

	for (int i = 0; i < 2 &&
	     (et == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN) ||
	      et == rte_cpu_to_be_16(RTE_ETHER_TYPE_QINQ)); i++) {
		struct rte_vlan_hdr *vh =
			rte_pktmbuf_mtod_offset(m, struct rte_vlan_hdr *, off);
		et = vh->eth_proto;
		off += sizeof(*vh);
	}
	if (et == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) &&
	    m->data_len >= off + sizeof(struct rte_ipv4_hdr)) {
		struct rte_ipv4_hdr *ip =
			rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, off);
		*cls = tos2class[ip->type_of_service];
	}
}

static inline void
flush_queue(uint16_t q)
{
	uint16_t n = qlen[q], sent;
	uint64_t b = 0;

	sent = rte_eth_tx_burst(g.tx_port, q, qbuf[q], n);
	for (uint16_t i = 0; i < sent; i++)
		b += qbytes[q][i];
	st[q].tx_pkts += sent;
	st[q].tx_bytes += b;
	for (uint16_t i = sent; i < n; i++) {
		st[q].drop_bytes += qbytes[q][i];
		rte_pktmbuf_free(qbuf[q][i]);
	}
	st[q].drop_pkts += n - sent;
	qlen[q] = 0;
}

/* ---------------------------------------------------------------- stats */

static struct rte_eth_stats es_rx_prev, es_tx_prev;

static void
print_stats(double dt, double t)
{
	struct rte_eth_stats es_rx, es_tx;
	double tot_tx = 0, tot_drop = 0;

	rte_eth_stats_get(g.rx_port, &es_rx);
	rte_eth_stats_get(g.tx_port, &es_tx);

	printf("\n[t=%.1fs] rx %.3f Mpps (looped back, dropped: %.3f Mpps), rx imissed %" PRIu64
	       ", tx port opackets %.3f Mpps, oerrors %" PRIu64 "\n", t,
	       (double)(rx_pkts - rx_pkts_prev) / dt / 1e6,
	       (double)(looped - looped_prev) / dt / 1e6,
	       es_rx.imissed - es_rx_prev.imissed,
	       (double)(es_tx.opackets - es_tx_prev.opackets) / dt / 1e6,
	       es_tx.oerrors - es_tx_prev.oerrors);
	printf("  inst class  txq   tx Gb/s  drop Gb/s  offered Gb/s  drop %%\n");

	for (uint16_t i = 0; i < g.n_inst; i++) {
		double inst_tx = 0, inst_drop = 0;

		for (uint16_t c = 0; c < g.n_class; c++) {
			uint16_t q = i * g.n_class + c;
			uint64_t txb = st[q].tx_bytes - st_prev[q].tx_bytes;
			uint64_t drb = st[q].drop_bytes - st_prev[q].drop_bytes;
			uint64_t txp = st[q].tx_pkts - st_prev[q].tx_pkts;
			uint64_t drp = st[q].drop_pkts - st_prev[q].drop_pkts;
			double tx = (double)txb * 8 / dt / 1e9;
			double dr = (double)drb * 8 / dt / 1e9;

			if (txp + drp == 0)
				continue;
			printf("  %4u %5u %4u  %8.3f  %9.3f  %12.3f  %6.2f\n", i, c, q,
			       tx, dr, tx + dr, 100.0 * (double)drp / (double)(txp + drp));
			if (g.csv)
				printf("CSV,%.3f,%u,%u,%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64
				       ",%" PRIu64 "\n", t, i, c, q, txp, txb, drp, drb);
			inst_tx += tx;
			inst_drop += dr;
		}
		if (inst_tx + inst_drop > 0)
			printf("  %4u   all       %8.3f  %9.3f  %12.3f\n", i, inst_tx,
			       inst_drop, inst_tx + inst_drop);
		tot_tx += inst_tx;
		tot_drop += inst_drop;
	}
	printf("   all   all       %8.3f  %9.3f  %12.3f   (L2 bytes, no framing)\n",
	       tot_tx, tot_drop, tot_tx + tot_drop);

	memcpy(st_prev, st, sizeof(st));
	rx_pkts_prev = rx_pkts;
	looped_prev = looped;
	es_rx_prev = es_rx;
	es_tx_prev = es_tx;
	fflush(stdout);
}

/* ---------------------------------------------------------------- main */

int
main(int argc, char **argv)
{
	struct rte_eth_dev_info info;
	struct rte_mempool *mp;
	struct rte_mbuf *pkts[BURST];
	uint16_t nb_txq;
	uint64_t hz, start, next, last;
	unsigned int nb_mbufs;
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "EAL init failed\n");
	argc -= ret;
	argv += ret;
	if (parse_args(argc, argv)) {
		usage(argv[0]);
		rte_exit(EXIT_FAILURE, "bad arguments\n");
	}
	if (!rte_eth_dev_is_valid_port(g.rx_port) || !rte_eth_dev_is_valid_port(g.tx_port))
		rte_exit(EXIT_FAILURE, "invalid port (%u ports available)\n",
			 rte_eth_dev_count_avail());

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	rte_eth_dev_info_get(g.tx_port, &info);
	g.is_ice = strcmp(info.driver_name, "net_ice") == 0;
	nb_txq = g.n_inst * g.n_class;

	nb_mbufs = RTE_MAX(nb_txq * (g.txd + BURST) + g.rxd + 8192u, 16383u);
	mp = rte_pktmbuf_pool_create("mbufs", nb_mbufs, 256, 0,
				     RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mp == NULL)
		rte_exit(EXIT_FAILURE, "mempool (%u mbufs) failed\n", nb_mbufs);

	if (g.rx_port == g.tx_port) {
		port_init(g.tx_port, 1, nb_txq, mp);
	} else {
		port_init(g.rx_port, 1, 1, mp);
		port_init(g.tx_port, 1, nb_txq, mp);
	}

	rte_eth_macaddr_get(g.tx_port, &g.tx_mac);
	{
		char buf[RTE_ETHER_ADDR_FMT_SIZE];

		rte_ether_format_addr(buf, sizeof(buf), &g.tx_mac);
		printf("frames leave with source MAC %s (port %u); frames arriving with it "
		       "are dropped as looped\n", buf, g.tx_port);
	}

	if (g.probe) {
		if (probe_caps(g.tx_port, true) < 0 && g.is_ice) {
			int l = detect_levels();

			printf("ice: %d usable TM levels by trial (leaf at level %d)\n",
			       l, l - 1);
		}
		rte_eal_cleanup();
		return 0;
	}
	if (g.no_tm)
		printf("TM: not configured, driver default tree (--no-tm)\n");
	else
		tm_build();

	if (g.rx_port != g.tx_port)
		port_start(g.rx_port);
	port_start(g.tx_port);

	printf("forwarding port %u -> port %u, %u Tx queues, q = instance * %u + class;"
	       " Ctrl-C to stop\n", g.rx_port, g.tx_port, nb_txq, g.n_class);

	hz = rte_get_tsc_hz();
	start = last = rte_rdtsc();
	next = start + hz * g.stats_ms / 1000;
	rte_eth_stats_get(g.rx_port, &es_rx_prev);
	rte_eth_stats_get(g.tx_port, &es_tx_prev);

	while (!force_quit) {
		uint16_t nb = rte_eth_rx_burst(g.rx_port, 0, pkts, BURST);
		uint64_t now;

		rx_pkts += nb;
		for (uint16_t i = 0; i < nb; i++) {
			struct rte_ether_hdr *eth =
				rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
			uint16_t inst, cls, q;

			/* a frame we sent ourselves (flooded back by a switch):
			 * forwarding it again would loop */
			if (rte_is_same_ether_addr(&eth->src_addr, &g.tx_mac)) {
				looped++;
				rte_pktmbuf_free(pkts[i]);
				continue;
			}
			classify(pkts[i], &inst, &cls);
			rte_ether_addr_copy(&g.tx_mac, &eth->src_addr);
			if (g.set_dst)
				rte_ether_addr_copy(&g.dst_mac, &eth->dst_addr);
			q = inst * g.n_class + cls;
			if (qlen[q] == 0)
				active[n_active++] = q;
			qbytes[q][qlen[q]] = pkts[i]->pkt_len;
			qbuf[q][qlen[q]++] = pkts[i];
			if (qlen[q] == BURST)
				flush_queue(q);  /* stays in active[]; flushed again if refilled */
		}
		for (uint16_t a = 0; a < n_active; a++)
			if (qlen[active[a]])
				flush_queue(active[a]);
		n_active = 0;

		now = rte_rdtsc();
		if (now >= next) {
			print_stats((double)(now - last) / (double)hz,
				    (double)(now - start) / (double)hz);
			last = now;
			next = now + hz * g.stats_ms / 1000;
		}
	}

	printf("\nstopping\n");
	rte_eth_dev_stop(g.tx_port);
	if (g.rx_port != g.tx_port)
		rte_eth_dev_stop(g.rx_port);
	rte_eal_cleanup();
	return 0;
}
