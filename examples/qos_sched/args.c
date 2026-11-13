/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <locale.h>
#include <unistd.h>
#include <limits.h>
#include <getopt.h>

#include <rte_log.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_string_fns.h>

#include "main.h"

#define APP_NAME "qos_sched"
#define MAX_OPT_VALUES 8
#define SYS_CPU_DIR "/sys/devices/system/cpu/cpu%u/topology/"

static uint32_t app_main_core = 1;

/* retry queue size and statistics switches (pending_stats.h, ctrl_stats.h) */
uint32_t pending_size = PENDING_DEFAULT;
uint32_t pending_mask = PENDING_DEFAULT - 1;
bool stats_on = true;
uint32_t stats_win_ms = 100;
uint32_t watch_us = 1000;
uint32_t backlog_us = 100;
static uint32_t app_numa_mask;
static uint64_t app_used_port_mask = 0;
static uint64_t app_used_rx_port_mask = 0;
static uint64_t app_used_tx_port_mask = 0;
/* a port used by more than one pfc: only allowed in PF mode (--pf-tree) */
static bool app_port_shared = false;


static const char usage[] =
	"                                                                               \n"
	"    %s <APP PARAMS>                                                            \n"
	"                                                                               \n"
	"Application mandatory parameters:                                              \n"
	"    --pfc \"RX PORT, TX PORT, RX LCORE, WT LCORE\" : Packet flow configuration \n"
	"           multiple pfc can be configured in command line                      \n"
	"                                                                               \n"
	"Application optional parameters:                                               \n"
	"    -i      : run in interactive mode (default value is %u)                    \n"
	"    --mnc I : main core index (default value is %u)                            \n"
	"    --rsz \"A, B, C\" :   Ring sizes                                           \n"
	"           A = Size (in number of buffer descriptors) of each of the NIC RX    \n"
	"               rings read by the I/O RX lcores (default value is %u)           \n"
	"           B = Size (in number of elements) of each of the SW rings used by the\n"
	"               I/O RX lcores to send packets to worker lcores (default value is\n"
	"               %u)                                                             \n"
	"           C = Size (in number of buffer descriptors) of each of the NIC TX    \n"
	"               rings written by worker lcores (default value is %u)            \n"
	"    --bsz \"A, B, C, D\": Burst sizes                                          \n"
	"           A = I/O RX lcore read burst size from NIC RX (default value is %u)  \n"
	"           B = I/O RX lcore write burst size to output SW rings,               \n"
	"               Worker lcore read burst size from input SW rings,               \n"
	"               QoS enqueue size (default value is %u)                          \n"
	"           C = QoS dequeue size (default value is %u)                          \n"
	"           D = Worker lcore write burst size to NIC TX (default value is %u)   \n"
	"    --msz M : Mempool size (in number of mbufs) for each pfc (default %u)      \n"
	"    --rth \"A, B, C\" :   RX queue threshold parameters                        \n"
	"           A = RX prefetch threshold (default value is %u)                     \n"
	"           B = RX host threshold (default value is %u)                         \n"
	"           C = RX write-back threshold (default value is %u)                   \n"
	"    --tth \"A, B, C\" :   TX queue threshold parameters                        \n"
	"           A = TX prefetch threshold (default value is %u)                     \n"
	"           B = TX host threshold (default value is %u)                         \n"
	"           C = TX write-back threshold (default value is %u)                   \n"
	"    --cfg FILE : profile configuration to load                                 \n"
	"    --mode NAME : mixed-thread backpressure mode (default qbc, or set at build) \n"
	"           none|qbc|cbc|rej|priobp|priobp_stats|pab_op|aggbp|pertcdequeue|      \n"
	"           prioprop (priobp_stats = PAB, pab_op = order-preserving PAB)        \n"
	"    --cbc-poll US : CBC completion poll period T_poll in us (default %u)       \n"
	"    --cbc-limit L : CBC limit on outstanding packets per TxQ (default N_desc)  \n"
	"    --rej-add-step A : REJ additive window step (default %u)                   \n"
	"    --rej-grow-streak K : REJ full transmits before growing W (default %u)     \n"
	"    --pf-tree class|instance|default : PF mode, all pfc share the PF port(s);   \n"
	"           pfc i = instance i: RX queue i (rte_flow on its MAC), TX queues     \n"
	"           8i..8i+7; NIC tree with classes above instances (class), instances \n"
	"           above classes (instance) or the driver's default tree (default)     \n"
	"    --pf-rate-gbps R : PF mode port shaper in Gb/s, 0 = none (default 25)      \n"
	"    --pf-tc-map \"q0,..,q12\" : traffic class -> one of the 8 TX queues of     \n"
	"           the instance (default scheduler order: 0,1,2,3,4,5,6,7,7,7,7,7,7)   \n"
	"    --pf-inst-mac MAC : MAC of instance 0, instance i adds i to the last byte  \n"
	"           (default 00:11:22:33:44:00, the Ixia gateway MACs)                  \n"
	"    --pf-levels L : TM tree depth (default: detected)                          \n"
	"    --pf-dst-mac MAC : static MACs: source = tx port MAC, destination = MAC   \n"
	"           with byte 1 + instance (Ixia upstream 00:<i>:01:00:00:01)           \n"
	"    --pq-size N : retry (pending) queue size per TC in packets, a power of   \n"
	"           two in [16, 4096] (default 512)                                   \n"
	"    --no-stats : disable all run statistics in the data path (ctrl_stats,   \n"
	"           pending stats, loop cycles, watched pipes), to measure their cost \n"
	"    --stats-win-ms MS : window of the peak gauges pq_max_win and             \n"
	"           qlen_max_win (default 100)                                        \n"
	"    --watch-pipes F:P[,P..] : watch the scheduler queues of pipes P (subport \n"
	"           0) of instance F (pfc index from 0), up to 8 pipes; repeat the    \n"
	"           option for each instance                                          \n"
	"    --watch-us US : read period of the watched pipes (default 1000)          \n"
	"    --backlog-us US : read period of the per-TC scheduler backlog (sched_enq,\n"
	"           sched_drop, backlog; subport 0) (default 100)                     \n"
	"    --txq-map hplp|pertc : scheduler TC -> NIC TX queue outside PF mode.     \n"
	"           hplp: TC0 on queue 0, all other TCs share queue 1. pertc: TC i   \n"
	"           on queue i. Default: hplp on iavf, pertc otherwise (cnxk)       \n"
;

/* display usage */
static void
app_usage(const char *prgname)
{
	printf(usage, prgname, APP_INTERACTIVE_DEFAULT, app_main_core,
		APP_RX_DESC_DEFAULT, APP_RING_SIZE, APP_TX_DESC_DEFAULT,
		MAX_PKT_RX_BURST, PKT_ENQUEUE, PKT_DEQUEUE,
		MAX_PKT_TX_BURST, NB_MBUF,
		RX_PTHRESH, RX_HTHRESH, RX_WTHRESH,
		TX_PTHRESH, TX_HTHRESH, TX_WTHRESH,
		CBC_POLL_US, REJ_ADD_STEP, REJ_GROW_STREAK
		);
}



/* returns:
	 number of values parsed
	-1 in case of error
*/
static int
app_parse_opt_vals(const char *conf_str, char separator, uint32_t n_vals, uint32_t *opt_vals)
{
	char *string;
	int i, n_tokens;
	char *tokens[MAX_OPT_VALUES];

	if (conf_str == NULL || opt_vals == NULL || n_vals == 0 || n_vals > MAX_OPT_VALUES)
		return -1;

	/* duplicate configuration string before splitting it to tokens */
	string = strdup(conf_str);
	if (string == NULL)
		return -1;

	n_tokens = rte_strsplit(string, strnlen(string, 32), tokens, n_vals, separator);

	if (n_tokens > MAX_OPT_VALUES) {
		free(string);
		return -1;
	}

	for (i = 0; i < n_tokens; i++)
		opt_vals[i] = (uint32_t)atol(tokens[i]);

	free(string);

	return n_tokens;
}

static int
app_parse_ring_conf(const char *conf_str)
{
	int ret;
	uint32_t vals[3];

	ret = app_parse_opt_vals(conf_str, ',', 3, vals);
	if (ret != 3)
		return ret;

	ring_conf.rx_size = vals[0];
	ring_conf.ring_size = vals[1];
	ring_conf.tx_size = vals[2];

	return 0;
}

static int
app_parse_rth_conf(const char *conf_str)
{
	int ret;
	uint32_t vals[3];

	ret = app_parse_opt_vals(conf_str, ',', 3, vals);
	if (ret != 3)
		return ret;

	rx_thresh.pthresh = (uint8_t)vals[0];
	rx_thresh.hthresh = (uint8_t)vals[1];
	rx_thresh.wthresh = (uint8_t)vals[2];

	return 0;
}

static int
app_parse_tth_conf(const char *conf_str)
{
	int ret;
	uint32_t vals[3];

	ret = app_parse_opt_vals(conf_str, ',', 3, vals);
	if (ret != 3)
		return ret;

	tx_thresh.pthresh = (uint8_t)vals[0];
	tx_thresh.hthresh = (uint8_t)vals[1];
	tx_thresh.wthresh = (uint8_t)vals[2];

	return 0;
}

static int
app_parse_flow_conf(const char *conf_str)
{
	int ret;
	uint32_t vals[5];
	struct flow_conf *pconf;
	uint64_t mask;

	memset(vals, 0, sizeof(vals));
	ret = app_parse_opt_vals(conf_str, ',', 6, vals);
	if (ret < 4 || ret > 5)
		return ret;

	pconf = &qos_conf[nb_pfc];

	pconf->rx_port = vals[0];
	pconf->tx_port = vals[1];
	pconf->rx_core = vals[2];
	pconf->wt_core = vals[3];
	if (ret == 5)
		pconf->tx_core = vals[4];
	else
		pconf->tx_core = pconf->wt_core;

	if (pconf->rx_core == pconf->wt_core) {
		RTE_LOG(ERR, APP, "pfc %u: rx thread and worker thread cannot share same core\n", nb_pfc);
		return -1;
	}

	if (pconf->rx_port >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, APP, "pfc %u: invalid rx port %"PRIu16" index\n",
				nb_pfc, pconf->rx_port);
		return -1;
	}
	if (pconf->tx_port >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, APP, "pfc %u: invalid tx port %"PRIu16" index\n",
				nb_pfc, pconf->tx_port);
		return -1;
	}

	/* ports shared between pfc are checked after parsing: PF mode allows it */
	mask = 1lu << pconf->rx_port;
	if (app_used_rx_port_mask & mask)
		app_port_shared = true;
	app_used_rx_port_mask |= mask;
	app_used_port_mask |= mask;

	mask = 1lu << pconf->tx_port;
	if (app_used_tx_port_mask & mask)
		app_port_shared = true;
	app_used_tx_port_mask |= mask;
	app_used_port_mask |= mask;

	nb_pfc++;

	return 0;
}

static int
app_parse_burst_conf(const char *conf_str)
{
	int ret;
	uint32_t vals[4];

	ret = app_parse_opt_vals(conf_str, ',', 4, vals);
	if (ret != 4)
		return ret;

	burst_conf.rx_burst    = (uint16_t)vals[0];
	burst_conf.ring_burst  = (uint16_t)vals[1];
	burst_conf.qos_dequeue = (uint16_t)vals[2];
	burst_conf.tx_burst    = (uint16_t)vals[3];

	return 0;
}

enum {
#define OPT_PFC "pfc"
	OPT_PFC_NUM = 256,
#define OPT_MNC "mnc"
	OPT_MNC_NUM,
#define OPT_RSZ "rsz"
	OPT_RSZ_NUM,
#define OPT_BSZ "bsz"
	OPT_BSZ_NUM,
#define OPT_MSZ "msz"
	OPT_MSZ_NUM,
#define OPT_RTH "rth"
	OPT_RTH_NUM,
#define OPT_TTH "tth"
	OPT_TTH_NUM,
#define OPT_CFG "cfg"
	OPT_CFG_NUM,
#define OPT_MODE "mode"
	OPT_MODE_NUM,
#define OPT_CBC_POLL "cbc-poll"
	OPT_CBC_POLL_NUM,
#define OPT_CBC_LIMIT "cbc-limit"
	OPT_CBC_LIMIT_NUM,
#define OPT_REJ_ADD "rej-add-step"
	OPT_REJ_ADD_NUM,
#define OPT_REJ_GROW "rej-grow-streak"
	OPT_REJ_GROW_NUM,
#define OPT_PF_TREE "pf-tree"
	OPT_PF_TREE_NUM,
#define OPT_PF_RATE "pf-rate-gbps"
	OPT_PF_RATE_NUM,
#define OPT_PF_TC_MAP "pf-tc-map"
	OPT_PF_TC_MAP_NUM,
#define OPT_PF_MAC "pf-inst-mac"
	OPT_PF_MAC_NUM,
#define OPT_PF_LEVELS "pf-levels"
	OPT_PF_LEVELS_NUM,
#define OPT_PF_DST_MAC "pf-dst-mac"
	OPT_PF_DST_MAC_NUM,
#define OPT_TXQ_MAP "txq-map"
	OPT_TXQ_MAP_NUM,
#define OPT_PQ_SIZE "pq-size"
	OPT_PQ_SIZE_NUM,
#define OPT_NO_STATS "no-stats"
	OPT_NO_STATS_NUM,
#define OPT_STATS_WIN "stats-win-ms"
	OPT_STATS_WIN_NUM,
#define OPT_WATCH_PIPES "watch-pipes"
	OPT_WATCH_PIPES_NUM,
#define OPT_WATCH_US "watch-us"
	OPT_WATCH_US_NUM,
#define OPT_BACKLOG_US "backlog-us"
	OPT_BACKLOG_US_NUM,
};

/*
 * --watch-pipes F:P[,P...]: pipes of subport 0 watched in instance F.
 * The pipe range is checked against the cfg in app_init (it is not loaded yet).
 */
static int
app_parse_watch_pipes(const char *arg)
{
	char buf[256];
	char *end, *save = NULL, *tok;
	unsigned long f;

	if (strlen(arg) >= sizeof(buf))
		return -1;
	snprintf(buf, sizeof(buf), "%s", arg);
	f = strtoul(buf, &end, 10);
	if (end == buf || *end != ':' || f >= MAX_DATA_STREAMS)
		return -1;

	struct ctrl_stats *cs = &qos_conf[f].cs;

	cs->n_watch = 0;
	for (tok = strtok_r(end + 1, ",", &save); tok != NULL;
			tok = strtok_r(NULL, ",", &save)) {
		unsigned long pipe = strtoul(tok, &end, 10);

		if (end == tok || *end != '\0' || pipe >= MAX_SCHED_PIPES ||
				cs->n_watch >= CS_WATCH_MAX)
			return -1;
		cs->watch_pipe[cs->n_watch++] = (uint32_t)pipe;
	}
	return cs->n_watch > 0 ? 0 : -1;
}

/*
 * Parses the argument given in the command line of the application,
 * calculates mask for used cores and initializes EAL with calculated core mask
 */
int
app_parse_args(int argc, char **argv)
{
	int opt, ret;
	int option_index;
	char *prgname = argv[0];
	uint32_t i;

	static struct option lgopts[] = {
		{OPT_PFC, 1, NULL, OPT_PFC_NUM},
		{OPT_MNC, 1, NULL, OPT_MNC_NUM},
		{OPT_RSZ, 1, NULL, OPT_RSZ_NUM},
		{OPT_BSZ, 1, NULL, OPT_BSZ_NUM},
		{OPT_MSZ, 1, NULL, OPT_MSZ_NUM},
		{OPT_RTH, 1, NULL, OPT_RTH_NUM},
		{OPT_TTH, 1, NULL, OPT_TTH_NUM},
		{OPT_CFG, 1, NULL, OPT_CFG_NUM},
		{OPT_MODE, 1, NULL, OPT_MODE_NUM},
		{OPT_CBC_POLL, 1, NULL, OPT_CBC_POLL_NUM},
		{OPT_CBC_LIMIT, 1, NULL, OPT_CBC_LIMIT_NUM},
		{OPT_REJ_ADD, 1, NULL, OPT_REJ_ADD_NUM},
		{OPT_REJ_GROW, 1, NULL, OPT_REJ_GROW_NUM},
		{OPT_PF_TREE, 1, NULL, OPT_PF_TREE_NUM},
		{OPT_PF_RATE, 1, NULL, OPT_PF_RATE_NUM},
		{OPT_PF_TC_MAP, 1, NULL, OPT_PF_TC_MAP_NUM},
		{OPT_PF_MAC, 1, NULL, OPT_PF_MAC_NUM},
		{OPT_PF_LEVELS, 1, NULL, OPT_PF_LEVELS_NUM},
		{OPT_PF_DST_MAC, 1, NULL, OPT_PF_DST_MAC_NUM},
		{OPT_TXQ_MAP, 1, NULL, OPT_TXQ_MAP_NUM},
		{OPT_PQ_SIZE, 1, NULL, OPT_PQ_SIZE_NUM},
		{OPT_NO_STATS, 0, NULL, OPT_NO_STATS_NUM},
		{OPT_STATS_WIN, 1, NULL, OPT_STATS_WIN_NUM},
		{OPT_WATCH_PIPES, 1, NULL, OPT_WATCH_PIPES_NUM},
		{OPT_WATCH_US, 1, NULL, OPT_WATCH_US_NUM},
		{OPT_BACKLOG_US, 1, NULL, OPT_BACKLOG_US_NUM},
		{NULL,    0, 0,    0          }
	};

	/* initialize EAL first */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		return -1;

	argc -= ret;
	argv += ret;

	/* set en_US locale to print big numbers with ',' */
	setlocale(LC_NUMERIC, "en_US.utf-8");

	while ((opt = getopt_long(argc, argv, "i",
		lgopts, &option_index)) != EOF) {

			switch (opt) {
			case 'i':
				printf("Interactive-mode selected\n");
				interactive = 1;
				break;
			/* long options */

			case OPT_PFC_NUM:
				ret = app_parse_flow_conf(optarg);
				if (ret) {
					RTE_LOG(ERR, APP, "Invalid pipe configuration %s\n",
							optarg);
					return -1;
				}
				break;

			case OPT_MNC_NUM:
				app_main_core = (uint32_t)atoi(optarg);
				break;

			case OPT_RSZ_NUM:
				ret = app_parse_ring_conf(optarg);
				if (ret) {
					RTE_LOG(ERR, APP, "Invalid ring configuration %s\n",
							optarg);
					return -1;
				}
				break;

			case OPT_BSZ_NUM:
				ret = app_parse_burst_conf(optarg);
				if (ret) {
					RTE_LOG(ERR, APP, "Invalid burst configuration %s\n",
							optarg);
					return -1;
				}
				break;

			case OPT_MSZ_NUM:
				mp_size = atoi(optarg);
				if (mp_size <= 0) {
					RTE_LOG(ERR, APP, "Invalid mempool size %s\n",
							optarg);
					return -1;
				}
				break;

			case OPT_RTH_NUM:
				ret = app_parse_rth_conf(optarg);
				if (ret) {
					RTE_LOG(ERR, APP, "Invalid RX threshold configuration %s\n",
							optarg);
					return -1;
				}
				break;

			case OPT_TTH_NUM:
				ret = app_parse_tth_conf(optarg);
				if (ret) {
					RTE_LOG(ERR, APP, "Invalid TX threshold configuration %s\n",
							optarg);
					return -1;
				}
				break;

			case OPT_CFG_NUM:
				cfg_profile = optarg;
				break;

			case OPT_MODE_NUM:
				if (mixed_mode_parse(optarg)) {
					RTE_LOG(ERR, APP, "Invalid --mode %s (expected %s)\n",
							optarg, mixed_mode_list());
					return -1;
				}
				break;

			case OPT_CBC_POLL_NUM:
				if (atoi(optarg) <= 0) {
					RTE_LOG(ERR, APP, "Invalid --cbc-poll %s\n", optarg);
					return -1;
				}
				cbc_poll_us = (uint32_t)atoi(optarg);
				break;

			case OPT_CBC_LIMIT_NUM:
				if (atoi(optarg) <= 0) {
					RTE_LOG(ERR, APP, "Invalid --cbc-limit %s\n", optarg);
					return -1;
				}
				cbc_limit = (uint32_t)atoi(optarg);
				break;

			case OPT_REJ_ADD_NUM:
				if (atoi(optarg) <= 0) {
					RTE_LOG(ERR, APP, "Invalid --rej-add-step %s\n", optarg);
					return -1;
				}
				rej_add_step = (uint32_t)atoi(optarg);
				break;

			case OPT_REJ_GROW_NUM:
				if (atoi(optarg) <= 0) {
					RTE_LOG(ERR, APP, "Invalid --rej-grow-streak %s\n", optarg);
					return -1;
				}
				rej_grow_streak = (uint32_t)atoi(optarg);
				break;

			case OPT_PF_TREE_NUM:
				if (pf_parse_tree(optarg)) {
					RTE_LOG(ERR, APP, "Invalid --pf-tree %s "
						"(expected class|instance|default)\n", optarg);
					return -1;
				}
				break;

			case OPT_TXQ_MAP_NUM:
				if (strcmp(optarg, "hplp") == 0)
					txq_map = TXQ_MAP_HPLP;
				else if (strcmp(optarg, "pertc") == 0)
					txq_map = TXQ_MAP_PERTC;
				else {
					RTE_LOG(ERR, APP, "Invalid --txq-map %s (hplp|pertc)\n", optarg);
					return -1;
				}
				break;

			case OPT_PF_RATE_NUM:
				pf_conf.rate_gbps = atof(optarg);
				if (pf_conf.rate_gbps < 0) {
					RTE_LOG(ERR, APP, "Invalid --pf-rate-gbps %s\n", optarg);
					return -1;
				}
				break;

			case OPT_PF_TC_MAP_NUM:
				if (pf_parse_tc_map(optarg)) {
					RTE_LOG(ERR, APP, "Invalid --pf-tc-map %s (13 values "
						"< %u)\n", optarg, PF_NQ);
					return -1;
				}
				break;

			case OPT_PF_MAC_NUM:
				if (rte_ether_unformat_addr(optarg, &pf_conf.inst_mac)) {
					RTE_LOG(ERR, APP, "Invalid --pf-inst-mac %s\n", optarg);
					return -1;
				}
				break;

			case OPT_PF_LEVELS_NUM:
				pf_conf.levels = atoi(optarg);
				break;

			case OPT_PF_DST_MAC_NUM:
				if (rte_ether_unformat_addr(optarg, &pf_conf.dst_mac)) {
					RTE_LOG(ERR, APP, "Invalid --pf-dst-mac %s\n", optarg);
					return -1;
				}
				pf_conf.set_dst = true;
				break;

			case OPT_PQ_SIZE_NUM: {
				long v = atol(optarg);

				if (v < PENDING_MIN || v > PENDING_MAX || (v & (v - 1))) {
					RTE_LOG(ERR, APP, "Invalid --pq-size %s (power of two "
						"in [%u, %u])\n", optarg, PENDING_MIN, PENDING_MAX);
					return -1;
				}
				pending_size = (uint32_t)v;
				pending_mask = pending_size - 1;
				break;
			}

			case OPT_NO_STATS_NUM:
				stats_on = false;
				break;

			case OPT_STATS_WIN_NUM:
				if (atoi(optarg) <= 0) {
					RTE_LOG(ERR, APP, "Invalid --stats-win-ms %s\n", optarg);
					return -1;
				}
				stats_win_ms = (uint32_t)atoi(optarg);
				break;

			case OPT_WATCH_PIPES_NUM:
				if (app_parse_watch_pipes(optarg)) {
					RTE_LOG(ERR, APP, "Invalid --watch-pipes %s (F:P[,P..], "
						"at most %u pipes)\n", optarg, CS_WATCH_MAX);
					return -1;
				}
				break;

			case OPT_WATCH_US_NUM:
				if (atoi(optarg) <= 0) {
					RTE_LOG(ERR, APP, "Invalid --watch-us %s\n", optarg);
					return -1;
				}
				watch_us = (uint32_t)atoi(optarg);
				break;

			case OPT_BACKLOG_US_NUM:
				if (atoi(optarg) <= 0) {
					RTE_LOG(ERR, APP, "Invalid --backlog-us %s\n", optarg);
					return -1;
				}
				backlog_us = (uint32_t)atoi(optarg);
				break;

			default:
				app_usage(prgname);
				return -1;
			}
	}

	/* the TC -> queue map is set per port: txq_map_apply(), pf_init_ports() */
	if (txq_map != TXQ_MAP_AUTO && pf_conf.shape != PF_TREE_OFF) {
		RTE_LOG(ERR, APP, "--txq-map does not apply in PF mode (use --pf-tc-map)\n");
		return -1;
	}

	if (nb_pfc == 0) {
		RTE_LOG(ERR, APP, "Packet flow not configured!\n");
		app_usage(prgname);
		return -1;
	}

	for (i = nb_pfc; i < MAX_DATA_STREAMS; i++)
		if (qos_conf[i].cs.n_watch) {
			RTE_LOG(ERR, APP, "--watch-pipes: instance %u is not configured "
				"(%u pfc)\n", i, nb_pfc);
			return -1;
		}

	if (app_port_shared && pf_conf.shape == PF_TREE_OFF) {
		RTE_LOG(ERR, APP, "several pfc use the same rx or tx port: "
			"only allowed in PF mode (--pf-tree)\n");
		return -1;
	}

	/* sanity check for cores assignment */
	for(i = 0; i < nb_pfc; i++) {
		if (qos_conf[i].rx_core >= RTE_MAX_LCORE) {
			RTE_LOG(ERR, APP, "pfc %u: invalid RX lcore index %u\n", i + 1,
					qos_conf[i].rx_core);
			return -1;
		}
		if (qos_conf[i].wt_core >= RTE_MAX_LCORE) {
			RTE_LOG(ERR, APP, "pfc %u: invalid WT lcore index %u\n", i + 1,
					qos_conf[i].wt_core);
			return -1;
		}
		uint32_t rx_sock = rte_lcore_to_socket_id(qos_conf[i].rx_core);
		uint32_t wt_sock = rte_lcore_to_socket_id(qos_conf[i].wt_core);
		if (rx_sock != wt_sock) {
			RTE_LOG(ERR, APP, "pfc %u: RX and WT must be on the same socket\n", i + 1);
			return -1;
		}
		app_numa_mask |= 1 << rte_lcore_to_socket_id(qos_conf[i].rx_core);
	}

	return 0;
}
