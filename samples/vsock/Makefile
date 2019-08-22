# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_SAMPLE_VSCAT) += vspoke.o

KBUILD_HOSTLDLIBS += -lreadline

ifdef CROSS_COMPILE
HOSTCC = $(CROSS_COMPILE)gcc
endif

hostprogs-$(CONFIG_SAMPLE_VSCAT) += vspoke.o

always := $(hostprogs-y)
