# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2020 Intel Corporation

.PHONY: all
all:
	cd build; \
	ninja; \
	ninja install;
	
