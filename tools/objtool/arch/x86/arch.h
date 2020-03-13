/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#ifndef _ARCH_H
#define _ARCH_H

#include <stdbool.h>
#include <linux/list.h>
#include "../../elf.h"
#include "cfi.h"

#include <asm/orc_types.h>
#include "../../orc.h"

enum insn_type {
	INSN_JUMP_CONDITIONAL,
	INSN_JUMP_UNCONDITIONAL,
	INSN_JUMP_DYNAMIC,
	INSN_JUMP_DYNAMIC_CONDITIONAL,
	INSN_CALL,
	INSN_CALL_DYNAMIC,
	INSN_RETURN,
	INSN_CONTEXT_SWITCH,
	INSN_STACK,
	INSN_BUG,
	INSN_NOP,
	INSN_STAC,
	INSN_CLAC,
	INSN_STD,
	INSN_CLD,
	INSN_OTHER,
};

enum op_dest_type {
	OP_DEST_REG,
	OP_DEST_REG_INDIRECT,
	OP_DEST_MEM,
	OP_DEST_PUSH,
	OP_DEST_PUSHF,
	OP_DEST_LEAVE,
};

struct op_dest {
	enum op_dest_type type;
	unsigned char reg;
	int offset;
};

enum op_src_type {
	OP_SRC_REG,
	OP_SRC_REG_INDIRECT,
	OP_SRC_CONST,
	OP_SRC_POP,
	OP_SRC_POPF,
	OP_SRC_ADD,
	OP_SRC_AND,
};

struct op_src {
	enum op_src_type type;
	unsigned char reg;
	int offset;
};

struct stack_op {
	struct op_dest dest;
	struct op_src src;
};

struct insn_state {
	struct cfi_reg cfa;
	struct cfi_reg regs[CFI_NUM_REGS];
	int stack_size;
	unsigned char type;
	bool bp_scratch;
	bool drap, end, uaccess, df;
	bool noinstr;
	s8 instr;
	unsigned int uaccess_stack;
	int drap_reg, drap_offset;
	struct cfi_reg vals[CFI_NUM_REGS];
};

struct instruction {
	struct list_head list;
	struct hlist_node hash;
	struct section *sec;
	unsigned long offset;
	unsigned int len;
	enum insn_type type;
	unsigned long immediate;
	bool alt_group, dead_end, ignore, hint, save, restore, ignore_alts;
	bool retpoline_safe;
	s8 instr;
	u8 visited;
	struct symbol *call_dest;
	struct instruction *jump_dest;
	struct instruction *first_jump_src;
	struct rela *jump_table;
	struct list_head alts;
	struct symbol *func;
	struct stack_op stack_op;
	struct insn_state state;
	struct orc_entry orc;
};

void arch_initial_func_cfi_state(struct cfi_state *state);

int arch_decode_instruction(struct elf *elf, struct section *sec,
			    unsigned long offset, unsigned int maxlen,
			    unsigned int *len, enum insn_type *type,
			    unsigned long *immediate, struct stack_op *op);

bool arch_callee_saved_reg(unsigned char reg);

#endif /* _ARCH_H */
