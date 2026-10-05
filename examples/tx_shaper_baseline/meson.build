# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

# Transmit controller (see the header of main.c):
#   none  Uncoordinated
#   pab   Priority-Aware Backpressure (retry buffer)
#   rej   REJ, outcome-based window (paper appendix)
#   cbc   Completion-Based Capacity (paper Algorithm 1)
#   qbc   Queue Occupancy-Based Capacity (paper Algorithm 2)
tx_controller = 'pab'

controllers = {
  'none': 'NONE',
  'pab': 'PAB',
  'rej': 'REJ',
  'cbc': 'CBC',
  'qbc': 'QBC',
}

if not controllers.has_key(tx_controller)
  error('tx_controller must be one of: none, pab, rej, cbc, qbc')
endif
cflags += ['-D' + controllers[tx_controller] + '=1']

allow_experimental_apis = true
sources = files(
        'main.c',
)
