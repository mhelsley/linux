/*
 * Copyright (C) 2019 Raphael Gault <raphael.gault@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ARM_INSN_DECODE_H
#define _ARM_INSN_DECODE_H

#include "../../../arch.h"

#define INSN_RESERVED	0b0000
#define INSN_UNKNOWN	0b0001
#define INSN_SVE_ENC	0b0010
#define INSN_UNALLOC	0b0011
#define INSN_DP_IMM	0b1001	//0x100x
#define INSN_BRANCH	0b1011	//0x101x
#define INSN_LD_ST_4	0b0100	//0bx1x0
#define INSN_LD_ST_6	0b0110	//0bx1x0
#define INSN_LD_ST_C	0b1100	//0bx1x0
#define INSN_LD_ST_E	0b1110	//0bx1x0
#define INSN_DP_REG_5	0b0101	//0bx101
#define INSN_DP_REG_D	0b1101	//0bx101
#define INSN_DP_SIMD_7	0b0111	//0bx111
#define INSN_DP_SIMD_F	0b1111	//0bx111

#define INSN_PCREL	0b001	//0b00x
#define INSN_ADD_SUB	0b010
#define INSN_ADD_TAG	0b011
#define INSN_LOGICAL	0b100
#define INSN_MOVE_WIDE	0b101
#define INSN_BITFIELD	0b110
#define INSN_EXTRACT	0b111

#define INSN_BR_UNCOND_IMM_L	0b0001
#define INSN_CP_BR_IMM_L	0b0010
#define INSN_TST_BR_IMM_L	0b0011
#define INSN_BR_COND_IMM	0b0100
#define INSN_BR_UNKNOWN_IMM	0b0111
#define INSN_BR_UNCOND_IMM_H	0b1001
#define INSN_CP_BR_IMM_H	0b1010
#define INSN_TST_BR_IMM_H	0b1011
#define INSN_BR_SYS_NO_IMM	0b1101

#define INSN_OP1_HINTS		0b01000000110010
#define INSN_OP1_BARRIERS	0b01000000110011

#define COMPOSED_INSN_REGS_NUM	2
#define INSN_COMPOSED	1

#define ADR_SOURCE	255

typedef int (*arm_decode_class)(u32 instr, enum insn_type *type,
				unsigned long *immediate, struct stack_op *op);

struct aarch64_insn_decoder {
	u32 mask;
	u32 value;
	arm_decode_class decode_func;
};

/* arm64 instruction classes */
int arm_decode_reserved(u32 instr, enum insn_type *type,
			unsigned long *immediate, struct stack_op *op);
int arm_decode_sve_encoding(u32 instr, enum insn_type *type,
			    unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_imm(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_reg(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct stack_op *op);
int arm_decode_br_sys(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct stack_op *op);
int arm_decode_ld_st(u32 instr, enum insn_type *type,
		     unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_simd(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct stack_op *op);
int arm_decode_unknown(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct stack_op *op);

/* arm64 data processing -- immediate subclasses */
int arm_decode_pcrel(u32 instr, enum insn_type *type,
		     unsigned long *immediate, struct stack_op *op);
int arm_decode_add_sub(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct stack_op *op);
int arm_decode_add_sub_tags(u32 instr, enum insn_type *type,
			    unsigned long *immediate, struct stack_op *op);
int arm_decode_logical(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct stack_op *op);
int arm_decode_move_wide(u32 instr, enum insn_type *type,
			 unsigned long *immediate, struct stack_op *op);
int arm_decode_bitfield(u32 instr, enum insn_type *type,
			unsigned long *immediate, struct stack_op *op);
int arm_decode_extract(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct stack_op *op);

/* arm64 branch, exception generation, system insn subclasses */
int arm_decode_br_uncond_imm(u32 instr, enum insn_type *type,
			     unsigned long *immediate, struct stack_op *op);
int arm_decode_br_comp_imm(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
int arm_decode_br_tst_imm(u32 instr, enum insn_type *type,
			  unsigned long *immediate, struct stack_op *op);
int arm_decode_br_cond_imm(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);

int arm_decode_br_uncond_reg(u32 instr, enum insn_type *type,
			     unsigned long *immediate, struct stack_op *op);

int arm_decode_br_reg(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct stack_op *op);
int arm_decode_except_gen(u32 instr, enum insn_type *type,
			  unsigned long *immediate, struct stack_op *op);
int arm_decode_hints(u32 instr, enum insn_type *type,
		     unsigned long *immediate, struct stack_op *op);
int arm_decode_barriers(u32 instr, enum insn_type *type,
			unsigned long *immediate, struct stack_op *op);
int arm_decode_pstate(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct stack_op *op);
int arm_decode_system_insn(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
int arm_decode_system_regs(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);

/* arm64 load/store instructions */
int arm_decode_adv_simd_mult(u32 instr, enum insn_type *type,
			     unsigned long *immediate, struct stack_op *op);
int arm_decode_adv_simd_mult_post(u32 instr, enum insn_type *type,
				  unsigned long *immediate,
				  struct stack_op *op);
int arm_decode_adv_simd_single(u32 instr, enum insn_type *type,
			       unsigned long *immediate, struct stack_op *op);
int arm_decode_adv_simd_single_post(u32 instr, enum insn_type *type,
				    unsigned long *immediate,
				    struct stack_op *op);
int arm_decode_ld_st_mem_tags(u32 instr, enum insn_type *type,
			      unsigned long *immediate, struct stack_op *op);
int arm_decode_ldapr_stlr_unsc_imm(u32 instr, enum insn_type *type,
				   unsigned long *immediate,
				   struct stack_op *op);
int arm_decode_ld_regs_literal(u32 instr, enum insn_type *type,
			       unsigned long *immediate, struct stack_op *op);
int arm_decode_ld_st_noalloc_pair_off(u32 instr, enum insn_type *type,
				      unsigned long *immediate,
				      struct stack_op *op);
int arm_decode_ld_st_regs_pair_post(u32 instr, enum insn_type *type,
				    unsigned long *immediate,
				    struct stack_op *op);
int arm_decode_ld_st_regs_pair_off(u32 instr, enum insn_type *type,
				   unsigned long *immediate,
				   struct stack_op *op);
int arm_decode_ld_st_regs_pair_pre(u32 instr, enum insn_type *type,
				   unsigned long *immediate,
				   struct stack_op *op);
int arm_decode_ld_st_regs_unsc_imm(u32 instr, enum insn_type *type,
				   unsigned long *immediate,
				   struct stack_op *op);
int arm_decode_ld_st_imm_post(u32 instr, enum insn_type *type,
			      unsigned long *immediate, struct stack_op *op);
int arm_decode_ld_st_imm_unpriv(u32 instr, enum insn_type *type,
				unsigned long *immediate, struct stack_op *op);
int arm_decode_ld_st_imm_pre(u32 instr, enum insn_type *type,
			     unsigned long *immediate, struct stack_op *op);
int arm_decode_atomic(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct stack_op *op);
int arm_decode_ld_st_regs_off(u32 instr, enum insn_type *type,
			      unsigned long *immediate, struct stack_op *op);
int arm_decode_ld_st_regs_pac(u32 instr, enum insn_type *type,
			      unsigned long *immediate, struct stack_op *op);
int arm_decode_ld_st_regs_unsigned(u32 instr, enum insn_type *type,
				   unsigned long *immediate,
				   struct stack_op *op);

int arm_decode_ld_st_exclusive(u32 instr, enum insn_type *type,
			       unsigned long *immediate, struct stack_op *op);

/* arm64 data processing -- registers instructions */
int arm_decode_dp_reg_1src(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_reg_2src(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_reg_3src(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_reg_adde(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_reg_cmpi(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_reg_eval(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_reg_cmpr(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_reg_rota(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_reg_csel(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_reg_addc(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_reg_adds(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
int arm_decode_dp_reg_logi(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op);
#endif /* _ARM_INSN_DECODE_H */
