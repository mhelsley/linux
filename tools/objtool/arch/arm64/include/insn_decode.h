/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _ARM_INSN_DECODE_H
#define _ARM_INSN_DECODE_H

#include "../../../arch.h"

#define INSN_RESERVED	0b0000
#define INSN_UNKNOWN	0b0001
#define INSN_UNALLOC	0b0011
#define INSN_DP_IMM	0b1001	//0x100x

#define NR_INSN_CLASS	16
#define INSN_CLASS(opcode)	(((opcode) >> 25) & (NR_INSN_CLASS - 1))

#define INSN_PCREL	0b001	//0b00x
#define INSN_MOVE_WIDE	0b101
#define INSN_BITFIELD	0b110
#define INSN_EXTRACT	0b111

typedef int (*arm_decode_class)(u32 instr, enum insn_type *type,
				unsigned long *immediate,
				struct list_head *ops_list);

/* arm64 instruction classes */
int arm_decode_dp_imm(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct list_head *ops_list);
int arm_decode_unknown(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct list_head *ops_list);

/* arm64 data processing -- immediate subclasses */
int arm_decode_pcrel(u32 instr, enum insn_type *type,
		     unsigned long *immediate, struct list_head *ops_list);
int arm_decode_move_wide(u32 instr, enum insn_type *type,
			 unsigned long *immediate, struct list_head *ops_list);
int arm_decode_bitfield(u32 instr, enum insn_type *type,
			unsigned long *immediate, struct list_head *ops_list);
int arm_decode_extract(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct list_head *ops_list);
#endif /* _ARM_INSN_DECODE_H */
