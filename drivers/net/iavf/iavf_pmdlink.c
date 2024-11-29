
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/queue.h>

#include <rte_string_fns.h>
#include <rte_memzone.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <ethdev_driver.h>
#include <rte_tcp.h>
#include <rte_sctp.h>
#include <rte_udp.h>
#include <rte_ip.h>
#include <rte_net.h>
#include <rte_vect.h>
#include <rte_vxlan.h>
#include <rte_gtp.h>
#include <rte_geneve.h>

#include "iavf.h"
#include "iavf_pmdlink.h"


int iavf_pmdlink_send_vf_msg(struct rte_eth_dev *dev, struct vf_msg_command *cmd) {
	
	struct iavf_adapter *ad = IAVF_DEV_PRIVATE_TO_ADAPTER(dev->data->dev_private);

	iavf_vchnl_send_vf_msg(ad, cmd);

        return 0;
}
