#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_udp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "virtchnl.h"

// ICE_SCHED_MIN_BW and ICE_SCHED_MAX_BW defined in ice.ko source in 'ice_type.h'.
#define ICE_SCHED_MIN_BW 500       /* in Kbps */
#define ICE_SCHED_MAX_BW 100000000 /* in Kbps */
#define IAVF_AQ_BUF_SZ 4096        // move this somewhere else, origin iavf.h
#define NO_OF_IAVF_TX_QUEUES 8

typedef uint16_t port_t;
typedef uint16_t teid_t;

void pmdlink_move_node(port_t port, teid_t source_teid, teid_t new_parent_teid);
void pmdlink_set_shaper(port_t port, teid_t teid, int tx_max, int tx_priority);
void pmdlink_delete_node(port_t port, teid_t node_teid);
// int pmdlink_add_node(port_t port, teid_t new_parent_teid);

// qos_node_t and the function pmdlink_read_topology() are the bridge between the low and high level APIs

typedef struct {
    uint32_t teid;
    uint32_t parent_teid;
    uint16_t tx_queue_id;
} qos_node_t;

qos_node_t *pmdlink_read_topology(port_t port);

// RTE_MAX_QUEUES_PER_PORT is 1024 in the current context - obviously (?) higher than practical for e810
// #define MAXQUEUES RTE_MAX_QUEUES_PER_PORT
// elsewhere, a uint8 is being used as queue index, so for now and to be safe use that (256)
#define MAXQUEUES 256
#define MAXPORTS RTE_MAX_ETHPORTS
// this is a quirk of the e810, not sure if it will always be applicable....
#define QOS_CHILD_LIMIT 8
#define QOS_ROOT_TEID 0

// hlapi.c - API higher implmentation

typedef struct shaper_conf {
   uint32_t shaper_rate;
   uint32_t tx_priority;
} shaper_conf;
typedef uint16_t teid_t;
struct binding {
    teid_t child;
    teid_t parent;
};

#define MAXCHILDLIMIT 8
typedef struct {
    uint32_t teid;
    uint8_t current_children_count;
} secondary_root_node_t;

struct port_hqos_state {
    teid_t root;
    teid_t leaves[MAXQUEUES];
    int leaf_count;
    int binding_count;
    struct binding bindings[MAXQUEUES * 3];
    secondary_root_node_t secondary_root_nodes[MAXCHILDLIMIT];
};

extern struct port_hqos_state *port_hqos_table[MAXPORTS];

// read-only diagnostic functions (diags.c)
void show_vf_qos_nodes(port_t port);
void show_topo_vf_qos_nodes(port_t port);
