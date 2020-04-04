# SPDX-License-Identifier: GPL-2.0
include ../../scripts/Makefile.include
include ../../scripts/Makefile.arch

# always use the host compiler
HOSTAR	?= ar
HOSTCC	?= gcc
HOSTLD	?= ld
AR	 = $(HOSTAR)
CC	 = $(HOSTCC)
LD	 = $(HOSTLD)

ifeq ($(srctree),)
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
endif

SAMPLES := foo.o

all: $(SAMPLES)

WARNINGS := $(EXTRA_WARNINGS) -Wno-switch-default -Wno-switch-enum -Wno-packed
CFLAGS   := -Werror $(WARNINGS) $(KBUILD_HOSTCFLAGS) -g $(INCLUDES)
LDFLAGS  += $(KBUILD_HOSTLDFLAGS)

export srctree OUTPUT CFLAGS SRCARCH
include $(srctree)/build/Makefile.include

$(SAMPLES:%.o): fixdep FORCE
	$(Q)$(MAKE) $(build)=$@

FORCE:

.PHONY: clean FORCE
