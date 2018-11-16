# SPDX-License-Identifier: GPL-2.0
include ../scripts/Makefile.include
include ../scripts/Makefile.arch

ifeq ($(ARCH),x86_64)
ARCH := x86
endif

# always use the host compiler
HOSTCC	?= gcc
HOSTLD	?= ld
CC	 = $(HOSTCC)
LD	 = $(HOSTLD)
AR	 = ar

ifeq ($(srctree),)
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
endif

SUBCMD_SRCDIR		= $(srctree)/tools/lib/subcmd/
LIBSUBCMD_OUTPUT	= $(if $(OUTPUT),$(OUTPUT),$(CURDIR)/)
LIBSUBCMD		= $(LIBSUBCMD_OUTPUT)libsubcmd.a

OBJTOOL    := $(OUTPUT)objtool
OBJTOOL_IN := $(OBJTOOL)-in.o

LIBELF_FLAGS := $(shell pkg-config libelf --cflags 2>/dev/null)
LIBELF_LIBS  := $(shell pkg-config libelf --libs 2>/dev/null || echo -lelf)

RECORDMCOUNT := $(OUTPUT)recordmcount
RECORDMCOUNT_IN := $(RECORDMCOUNT)-in.o
SORTEXTABLE := $(OUTPUT)sortextable
SORTEXTABLE_IN := $(SORTEXTABLE)-in.o
ifeq ($BUILD_C_RECORDMCOUNT),y)
all:  $(RECORDMCOUNT)
endif
ifeq ($(CONFIG_BUILDTIME_EXTABLE_SORT),y)
all: $(SORTEXTABLE)
endif

all: $(OBJTOOL)

INCLUDES := -I$(srctree)/tools/include \
	    -I$(srctree)/tools/arch/$(HOSTARCH)/include/uapi \
	    -I$(srctree)/tools/objtool/arch/$(ARCH)/include
WARNINGS := $(EXTRA_WARNINGS) -Wno-switch-default -Wno-switch-enum -Wno-packed
CFLAGS   += -Werror $(WARNINGS) $(KBUILD_HOSTCFLAGS) -g $(INCLUDES) $(LIBELF_FLAGS)
LDFLAGS  += $(LIBELF_LIBS) $(LIBSUBCMD) $(KBUILD_HOSTLDFLAGS)

# Allow old libelf to be used:
elfshdr := $(shell echo '$(pound)include <libelf.h>' | $(CC) $(CFLAGS) -x c -E - | grep elf_getshdr)
CFLAGS += $(if $(elfshdr),,-DLIBELF_USE_DEPRECATED)

AWK = awk
export srctree OUTPUT CFLAGS SRCARCH AWK
include $(srctree)/tools/build/Makefile.include

$(OBJTOOL_IN): fixdep FORCE
	@$(MAKE) $(build)=objtool

$(RECORDMCOUNT_IN): fixdep FORCE
	@$(MAKE) $(build)=recordmcount
$(SORTEXTABLE_IN): fixdep FORCE
	@$(MAKE) $(build)=sortextable

$(OBJTOOL): $(LIBSUBCMD) $(OBJTOOL_IN)
	@$(CONFIG_SHELL) ./sync-check.sh
	$(QUIET_LINK)$(CC) $(OBJTOOL_IN) $(LDFLAGS) -o $@

$(RECORDMCOUNT): $(RECORDMCOUNT_IN)
	$(QUIET_LINK)$(CC) $(RECORDMCOUNT_IN) $(KBUILD_HOSTLDFLAGS) -o $@
$(SORTEXTABLE): $(SORTEXTABLE_IN)
	$(QUIET_LINK)$(CC) $(SORTEXTABLE_IN) $(KBUILD_HOSTLDFLAGS) -o $@

$(LIBSUBCMD): fixdep FORCE
	$(Q)$(MAKE) -C $(SUBCMD_SRCDIR) OUTPUT=$(LIBSUBCMD_OUTPUT)

clean:
	$(call QUIET_CLEAN, objtool) $(RM) $(OBJTOOL) $(RECORDMCOUNT) $(SORTEXTABLE)
	$(Q)find $(OUTPUT) -name '*.o' -delete -o -name '\.*.cmd' -delete -o -name '\.*.d' -delete
	$(Q)$(RM) $(OUTPUT)arch/x86/lib/inat-tables.c $(OUTPUT)fixdep

FORCE:

.PHONY: clean FORCE
