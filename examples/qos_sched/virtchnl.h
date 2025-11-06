/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2021 Intel Corporation
 */

/* Description:
 * This header file describes the Virtual Function (VF) - Physical Function
 * (PF) communication protocol used by the drivers for all devices starting
 * from our 40G product line
 *
 * Admin queue buffer usage:
 * desc->opcode is always aqc_opc_send_msg_to_pf
 * flags, retval, datalen, and data addr are all used normally.
 * The Firmware copies the cookie fields when sending messages between the
 * PF and VF, but uses all other fields internally. Due to this limitation,
 * we must send all messages as "indirect", i.e. using an external buffer.
 *
 * All the VSI indexes are relative to the VF. Each VF can have maximum of
 * three VSIs. All the queue indexes are relative to the VSI.  Each VF can
 * have a maximum of sixteen queues for all of its VSIs.
 *
 * The PF is required to return a status code in v_retval for all messages
 * except RESET_VF, which does not require any response. The returned value
 * is of virtchnl_status_code type, defined in the shared type.h.
 *
 * In general, VF driver initialization should roughly follow the order of
 * these opcodes. The VF driver must first validate the API version of the
 * PF driver, then request a reset, then get resources, then configure
 * queues and interrupts. After these operations are complete, the VF
 * driver may start its queues, optionally add MAC and VLAN filters, and
 * process traffic.
 */

/* START GENERIC DEFINES
 * Need to ensure the following enums and defines hold the same meaning and
 * value in current and future projects
 */

/* Opcodes for VF-PF communication. These are placed in the v_opcode field
 * of the virtchnl_msg structure.
 */
enum virtchnl_ops {
    /* The PF sends status change events to VFs using
     * the VIRTCHNL_OP_EVENT opcode.
     * VFs send requests to the PF using the other ops.
     * Use of "advanced opcode" features must be negotiated as part of capabilities
     * exchange and are not considered part of base mode feature set.
     */
    VIRTCHNL_OP_UNKNOWN = 0,
    VIRTCHNL_OP_VERSION = 1, /* must ALWAYS be 1 */
    VIRTCHNL_OP_RESET_VF = 2,
    VIRTCHNL_OP_GET_VF_RESOURCES = 3,
    VIRTCHNL_OP_CONFIG_TX_QUEUE = 4,
    VIRTCHNL_OP_CONFIG_RX_QUEUE = 5,
    VIRTCHNL_OP_CONFIG_VSI_QUEUES = 6,
    VIRTCHNL_OP_CONFIG_IRQ_MAP = 7,
    VIRTCHNL_OP_ENABLE_QUEUES = 8,
    VIRTCHNL_OP_DISABLE_QUEUES = 9,
    VIRTCHNL_OP_ADD_ETH_ADDR = 10,
    VIRTCHNL_OP_DEL_ETH_ADDR = 11,
    VIRTCHNL_OP_ADD_VLAN = 12,
    VIRTCHNL_OP_DEL_VLAN = 13,
    VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE = 14,
    VIRTCHNL_OP_GET_STATS = 15,
    VIRTCHNL_OP_RSVD = 16,
    VIRTCHNL_OP_EVENT = 17, /* must ALWAYS be 17 */
    /* opcode 19 is reserved */
    /* opcodes 20, 21, and 22 are reserved */
    VIRTCHNL_OP_CONFIG_RSS_KEY = 23,
    VIRTCHNL_OP_CONFIG_RSS_LUT = 24,
    VIRTCHNL_OP_GET_RSS_HENA_CAPS = 25,
    VIRTCHNL_OP_SET_RSS_HENA = 26,
    VIRTCHNL_OP_ENABLE_VLAN_STRIPPING = 27,
    VIRTCHNL_OP_DISABLE_VLAN_STRIPPING = 28,
    VIRTCHNL_OP_REQUEST_QUEUES = 29,
    VIRTCHNL_OP_ENABLE_CHANNELS = 30,
    VIRTCHNL_OP_DISABLE_CHANNELS = 31,
    VIRTCHNL_OP_ADD_CLOUD_FILTER = 32,
    VIRTCHNL_OP_DEL_CLOUD_FILTER = 33,
    VIRTCHNL_OP_INLINE_IPSEC_CRYPTO = 34,
    /* opcodes 35 and 36 are reserved */
    VIRTCHNL_OP_DCF_CONFIG_BW = 37,
    VIRTCHNL_OP_DCF_VLAN_OFFLOAD = 38,
    VIRTCHNL_OP_DCF_CMD_DESC = 39,
    VIRTCHNL_OP_DCF_CMD_BUFF = 40,
    VIRTCHNL_OP_DCF_DISABLE = 41,
    VIRTCHNL_OP_DCF_GET_VSI_MAP = 42,
    VIRTCHNL_OP_DCF_GET_PKG_INFO = 43,
    VIRTCHNL_OP_GET_SUPPORTED_RXDIDS = 44,
    VIRTCHNL_OP_ADD_RSS_CFG = 45,
    VIRTCHNL_OP_DEL_RSS_CFG = 46,
    VIRTCHNL_OP_ADD_FDIR_FILTER = 47,
    VIRTCHNL_OP_DEL_FDIR_FILTER = 48,
    VIRTCHNL_OP_GET_MAX_RSS_QREGION = 50,
    VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS = 51,
    VIRTCHNL_OP_ADD_VLAN_V2 = 52,
    VIRTCHNL_OP_DEL_VLAN_V2 = 53,
    VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2 = 54,
    VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2 = 55,
    VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2 = 56,
    VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2 = 57,
    VIRTCHNL_OP_ENABLE_VLAN_FILTERING_V2 = 58,
    VIRTCHNL_OP_DISABLE_VLAN_FILTERING_V2 = 59,
    VIRTCHNL_OP_1588_PTP_GET_CAPS = 60,
    VIRTCHNL_OP_1588_PTP_GET_TIME = 61,
    VIRTCHNL_OP_GET_QOS_CAPS = 66,
    VIRTCHNL_OP_CONFIG_QUEUE_TC_MAP = 67,
    VIRTCHNL_OP_ENABLE_QUEUES_V2 = 107,
    VIRTCHNL_OP_DISABLE_QUEUES_V2 = 108,
    VIRTCHNL_OP_MAP_QUEUE_VECTOR = 111,
    VIRTCHNL_OP_CONFIG_QUEUE_BW = 112,
    VIRTCHNL_OP_CONFIG_QUANTA = 113,
    VIRTCHNL_OP_FLOW_SUBSCRIBE = 114,
    VIRTCHNL_OP_FLOW_UNSUBSCRIBE = 115,
    VIRTCHNL_OP_HQOS_TREE_READ = 131,
    VIRTCHNL_OP_HQOS_ELEMS_ADD = 132,
    VIRTCHNL_OP_HQOS_ELEMS_DEL = 133,
    VIRTCHNL_OP_HQOS_ELEMS_MOVE = 134,
    VIRTCHNL_OP_HQOS_ELEMS_CONF = 135,
    VIRTCHNL_OP_MAX,
};

static inline const char *virtchnl_op_str(enum virtchnl_ops v_opcode) {
    switch (v_opcode) {
    case VIRTCHNL_OP_UNKNOWN:
        return "VIRTCHNL_OP_UNKNOWN";
    case VIRTCHNL_OP_VERSION:
        return "VIRTCHNL_OP_VERSION";
    case VIRTCHNL_OP_RESET_VF:
        return "VIRTCHNL_OP_RESET_VF";
    case VIRTCHNL_OP_GET_VF_RESOURCES:
        return "VIRTCHNL_OP_GET_VF_RESOURCES";
    case VIRTCHNL_OP_CONFIG_TX_QUEUE:
        return "VIRTCHNL_OP_CONFIG_TX_QUEUE";
    case VIRTCHNL_OP_CONFIG_RX_QUEUE:
        return "VIRTCHNL_OP_CONFIG_RX_QUEUE";
    case VIRTCHNL_OP_CONFIG_VSI_QUEUES:
        return "VIRTCHNL_OP_CONFIG_VSI_QUEUES";
    case VIRTCHNL_OP_CONFIG_IRQ_MAP:
        return "VIRTCHNL_OP_CONFIG_IRQ_MAP";
    case VIRTCHNL_OP_ENABLE_QUEUES:
        return "VIRTCHNL_OP_ENABLE_QUEUES";
    case VIRTCHNL_OP_DISABLE_QUEUES:
        return "VIRTCHNL_OP_DISABLE_QUEUES";
    case VIRTCHNL_OP_ADD_ETH_ADDR:
        return "VIRTCHNL_OP_ADD_ETH_ADDR";
    case VIRTCHNL_OP_DEL_ETH_ADDR:
        return "VIRTCHNL_OP_DEL_ETH_ADDR";
    case VIRTCHNL_OP_ADD_VLAN:
        return "VIRTCHNL_OP_ADD_VLAN";
    case VIRTCHNL_OP_DEL_VLAN:
        return "VIRTCHNL_OP_DEL_VLAN";
    case VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE:
        return "VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE";
    case VIRTCHNL_OP_GET_STATS:
        return "VIRTCHNL_OP_GET_STATS";
    case VIRTCHNL_OP_RSVD:
        return "VIRTCHNL_OP_RSVD";
    case VIRTCHNL_OP_EVENT:
        return "VIRTCHNL_OP_EVENT";
    case VIRTCHNL_OP_CONFIG_RSS_KEY:
        return "VIRTCHNL_OP_CONFIG_RSS_KEY";
    case VIRTCHNL_OP_CONFIG_RSS_LUT:
        return "VIRTCHNL_OP_CONFIG_RSS_LUT";
    case VIRTCHNL_OP_GET_RSS_HENA_CAPS:
        return "VIRTCHNL_OP_GET_RSS_HENA_CAPS";
    case VIRTCHNL_OP_SET_RSS_HENA:
        return "VIRTCHNL_OP_SET_RSS_HENA";
    case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING:
        return "VIRTCHNL_OP_ENABLE_VLAN_STRIPPING";
    case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING:
        return "VIRTCHNL_OP_DISABLE_VLAN_STRIPPING";
    case VIRTCHNL_OP_REQUEST_QUEUES:
        return "VIRTCHNL_OP_REQUEST_QUEUES";
    case VIRTCHNL_OP_ENABLE_CHANNELS:
        return "VIRTCHNL_OP_ENABLE_CHANNELS";
    case VIRTCHNL_OP_DISABLE_CHANNELS:
        return "VIRTCHNL_OP_DISABLE_CHANNELS";
    case VIRTCHNL_OP_ADD_CLOUD_FILTER:
        return "VIRTCHNL_OP_ADD_CLOUD_FILTER";
    case VIRTCHNL_OP_DEL_CLOUD_FILTER:
        return "VIRTCHNL_OP_DEL_CLOUD_FILTER";
    case VIRTCHNL_OP_INLINE_IPSEC_CRYPTO:
        return "VIRTCHNL_OP_INLINE_IPSEC_CRYPTO";
    case VIRTCHNL_OP_DCF_CMD_DESC:
        return "VIRTCHNL_OP_DCF_CMD_DESC";
    case VIRTCHNL_OP_DCF_CMD_BUFF:
        return "VIRTCHNL_OP_DCF_CMD_BUFF";
    case VIRTCHNL_OP_DCF_DISABLE:
        return "VIRTCHNL_OP_DCF_DISABLE";
    case VIRTCHNL_OP_DCF_GET_VSI_MAP:
        return "VIRTCHNL_OP_DCF_GET_VSI_MAP";
    case VIRTCHNL_OP_GET_SUPPORTED_RXDIDS:
        return "VIRTCHNL_OP_GET_SUPPORTED_RXDIDS";
    case VIRTCHNL_OP_ADD_RSS_CFG:
        return "VIRTCHNL_OP_ADD_RSS_CFG";
    case VIRTCHNL_OP_DEL_RSS_CFG:
        return "VIRTCHNL_OP_DEL_RSS_CFG";
    case VIRTCHNL_OP_ADD_FDIR_FILTER:
        return "VIRTCHNL_OP_ADD_FDIR_FILTER";
    case VIRTCHNL_OP_DEL_FDIR_FILTER:
        return "VIRTCHNL_OP_DEL_FDIR_FILTER";
    case VIRTCHNL_OP_GET_MAX_RSS_QREGION:
        return "VIRTCHNL_OP_GET_MAX_RSS_QREGION";
    case VIRTCHNL_OP_ENABLE_QUEUES_V2:
        return "VIRTCHNL_OP_ENABLE_QUEUES_V2";
    case VIRTCHNL_OP_DISABLE_QUEUES_V2:
        return "VIRTCHNL_OP_DISABLE_QUEUES_V2";
    case VIRTCHNL_OP_MAP_QUEUE_VECTOR:
        return "VIRTCHNL_OP_MAP_QUEUE_VECTOR";
    case VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS:
        return "VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS";
    case VIRTCHNL_OP_ADD_VLAN_V2:
        return "VIRTCHNL_OP_ADD_VLAN_V2";
    case VIRTCHNL_OP_DEL_VLAN_V2:
        return "VIRTCHNL_OP_DEL_VLAN_V2";
    case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2:
        return "VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2";
    case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2:
        return "VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2";
    case VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2:
        return "VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2";
    case VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2:
        return "VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2";
    case VIRTCHNL_OP_ENABLE_VLAN_FILTERING_V2:
        return "VIRTCHNL_OP_ENABLE_VLAN_FILTERING_V2";
    case VIRTCHNL_OP_DISABLE_VLAN_FILTERING_V2:
        return "VIRTCHNL_OP_DISABLE_VLAN_FILTERING_V2";
    case VIRTCHNL_OP_1588_PTP_GET_CAPS:
        return "VIRTCHNL_OP_1588_PTP_GET_CAPS";
    case VIRTCHNL_OP_1588_PTP_GET_TIME:
        return "VIRTCHNL_OP_1588_PTP_GET_TIME";
    case VIRTCHNL_OP_FLOW_SUBSCRIBE:
        return "VIRTCHNL_OP_FLOW_SUBSCRIBE";
    case VIRTCHNL_OP_FLOW_UNSUBSCRIBE:
        return "VIRTCHNL_OP_FLOW_UNSUBSCRIBE";
    case VIRTCHNL_OP_MAX:
        return "VIRTCHNL_OP_MAX";
    default:
        return "Unsupported (update virtchnl.h)";
    }
}

/*
 * VIRTCHNL_OP_HQOS_READ_TREE
 * VIRTCHNL_OP_HQOS_ELEM_ADD
 * VIRTCHNL_OP_HQOS_ELEM_DEL
 * VIRTCHNL_OP_HQOS_ELEM_BW_SET
 * List with tc and queus HW QoS values
 */
struct virtchnl_hqos_cfg {
#define VIRTCHNL_HQOS_ELEM_TYPE_NODE 0
#define VIRTCHNL_HQOS_ELEM_TYPE_LEAF 1
    uint8_t node_type;
    uint8_t pad[7];
    uint32_t teid;
    uint32_t parent_teid;
    uint64_t tx_max;
    uint64_t tx_share;
    uint32_t tx_priority;
    uint32_t tx_weight;
    uint16_t vsi_handle;
    uint16_t tx_queue_id;
    uint32_t id;
};

struct virtchnl_hqos_cfg_list {
    uint16_t num_elem;
    uint8_t pad[6];
    struct virtchnl_hqos_cfg cfg[1];
};

struct vf_msg_command {
    uint32_t opcode;         // Operation code
    uint8_t *input_buffer;   // Input data for the operation
    uint32_t input_size;     // Size of input data
    uint8_t **output_buffer; // Pointer to output buffer
    uint32_t output_size;    // Size of the output buffer
};
