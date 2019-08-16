/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _ARM_INSN_DECODE_H
#define _ARM_INSN_DECODE_H

#include "../../../arch.h"

#define NR_INSN_CLASS	16
#define INSN_CLASS(opcode)	(((opcode) >> 25) & (NR_INSN_CLASS - 1))

typedef int (*arm_decode_class)(u32 instr, enum insn_type *type,
				unsigned long *immediate,
				struct list_head *ops_list);

#endif /* _ARM_INSN_DECODE_H */
