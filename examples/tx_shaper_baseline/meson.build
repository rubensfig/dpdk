# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

# Select either 'comp' or 'bql'
tx_controller = 'bql'

if tx_controller == 'comp'
  cflags += ['-DCOMP=1']
elif tx_controller == 'bql'
  cflags += ['-DBQL=1']
else
  error('tx_controller must be either comp or bql')
endif

allow_experimental_apis = true
sources = files(
        'main.c',
)
