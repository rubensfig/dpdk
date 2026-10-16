#ifndef _IAVF_PMDLINK_H_
#define _IAVF_PMDLINK_H_

#include <ethdev_driver.h>

struct vf_msg_command;

int iavf_pmdlink_send_vf_msg(struct rte_eth_dev *dev, struct vf_msg_command *cmd);

#endif /* _IAVF_PMDLINK_H_ */
