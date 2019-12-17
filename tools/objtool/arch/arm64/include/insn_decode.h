/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _ARM_INSN_DECODE_H
#define _ARM_INSN_DECODE_H

#include "../../../arch.h"

#define INSN_RESERVED	0b0000
#define INSN_UNKNOWN	0b0001
#define INSN_UNALLOC	0b0011
#define INSN_DP_IMM	0b1001	//0x100x
#define INSN_SYS_BRANCH	0b1011	//0x101x
#define INSN_LD_ST_4	0b0100	//0bx1x0
#define INSN_LD_ST_6	0b0110	//0bx1x0
#define INSN_LD_ST_C	0b1100	//0bx1x0
#define INSN_LD_ST_E	0b1110	//0bx1x0

#define NR_INSN_CLASS	16
#define INSN_CLASS(opcode)	(((opcode) >> 25) & (NR_INSN_CLASS - 1))

#define INSN_PCREL	0b001	//0b00x
#define INSN_ADD_SUB	0b010
#define INSN_ADD_TAG	0b011
#define INSN_LOGICAL	0b100
#define INSN_MOVE_WIDE	0b101
#define INSN_BITFIELD	0b110
#define INSN_EXTRACT	0b111

typedef int (*arm_decode_class)(u32 instr, enum insn_type *type,
				unsigned long *immediate,
				struct list_head *ops_list);

struct aarch64_insn_decoder {
	u32 mask;
	u32 value;
	arm_decode_class decode_func;
};

/* arm64 instruction classes */
int arm_decode_dp_imm(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct list_head *ops_list);
int arm_decode_br_sys(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct list_head *ops_list);
int arm_decode_ld_st(u32 instr, enum insn_type *type,
		     unsigned long *immediate, struct list_head *ops_list);
int arm_decode_unknown(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct list_head *ops_list);

/* arm64 data processing -- immediate subclasses */
int arm_decode_pcrel(u32 instr, enum insn_type *type,
		     unsigned long *immediate, struct list_head *ops_list);
int arm_decode_add_sub(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct list_head *ops_list);
int arm_decode_add_sub_tags(u32 instr, enum insn_type *type,
			    unsigned long *immediate,
			    struct list_head *ops_list);
int arm_decode_logical(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct list_head *ops_list);
int arm_decode_move_wide(u32 instr, enum insn_type *type,
			 unsigned long *immediate, struct list_head *ops_list);
int arm_decode_bitfield(u32 instr, enum insn_type *type,
			unsigned long *immediate, struct list_head *ops_list);
int arm_decode_extract(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct list_head *ops_list);

/* arm64 branch, exception generation, system insn subclasses */
int arm_decode_hints(u32 instr, enum insn_type *type,
		     unsigned long *immediate, struct list_head *ops_list);
int arm_decode_barriers(u32 instr, enum insn_type *type,
			unsigned long *immediate, struct list_head *ops_list);
int arm_decode_pstate(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct list_head *ops_list);
int arm_decode_system_insn(u32 instr, enum insn_type *type,
			   unsigned long *immediate,
			   struct list_head *ops_list);
int arm_decode_system_regs(u32 instr, enum insn_type *type,
			   unsigned long *immediate,
			   struct list_head *ops_list);
int arm_decode_except_gen(u32 instr, enum insn_type *type,
			  unsigned long *immediate, struct list_head *ops_list);
int arm_decode_br_uncond_imm(u32 instr, enum insn_type *type,
			     unsigned long *immediate,
			     struct list_head *ops_list);
int arm_decode_br_comp_imm(u32 instr, enum insn_type *type,
			   unsigned long *immediate,
			   struct list_head *ops_list);
int arm_decode_br_tst_imm(u32 instr, enum insn_type *type,
			  unsigned long *immediate, struct list_head *ops_list);
int arm_decode_br_cond_imm(u32 instr, enum insn_type *type,
			   unsigned long *immediate,
			   struct list_head *ops_list);
int arm_decode_br_uncond_reg(u32 instr, enum insn_type *type,
			     unsigned long *immediate,
			     struct list_head *ops_list);

/* arm64 load/store instructions */
int arm_decode_ld_st_regs_unsc_imm(u32 instr, enum insn_type *type,
				   unsigned long *immediate,
				   struct list_head *ops_list);
int arm_decode_ld_st_imm_post(u32 instr, enum insn_type *type,
			      unsigned long *immediate,
			      struct list_head *ops_list);
int arm_decode_ld_st_imm_unpriv(u32 instr, enum insn_type *type,
				unsigned long *immediate,
				struct list_head *ops_list);
int arm_decode_ld_st_imm_pre(u32 instr, enum insn_type *type,
			     unsigned long *immediate,
			     struct list_head *ops_list);
int arm_decode_ld_st_regs_off(u32 instr, enum insn_type *type,
			      unsigned long *immediate,
			      struct list_head *ops_list);
int arm_decode_ld_st_regs_unsigned(u32 instr, enum insn_type *type,
				   unsigned long *immediate,
				   struct list_head *ops_list);
#endif /* _ARM_INSN_DECODE_H */
