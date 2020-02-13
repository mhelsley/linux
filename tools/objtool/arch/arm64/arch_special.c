// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdlib.h>
#include <string.h>

#include <asm/aarch64-insn.h>

#include "../../special.h"
#include "../../warn.h"
#include "arch_special.h"
#include "bit_operations.h"

/*
 * The arm64_switch_table_detection_plugin generate an array of elements
 * described by the following structure.
 * Each jump table found in the compilation unit is associated with one of
 * entries of the array.
 */
struct switch_table_info {
	u64 switch_table_ref; // Relocation target referencing the beginning of the jump table
	u64 dyn_jump_ref; // Relocation target referencing the set of instructions setting up the jump to the table
	u64 nb_entries;
	u64 offset_unsigned;
} __attribute__((__packed__));

static bool insn_is_adr_pcrel(struct instruction *insn)
{
	u32 opcode = *(u32 *)(insn->sec->data->d_buf + insn->offset);

	return aarch64_insn_is_adr(opcode) || aarch64_insn_is_adrp(opcode);
}

static s64 next_offset(void *table, u8 entry_size, bool is_signed)
{
	if (!is_signed) {
		switch (entry_size) {
		case 1:
			return *(u8 *)(table);
		case 2:
			return *(u16 *)(table);
		default:
			return *(u32 *)(table);
		}
	} else {
		switch (entry_size) {
		case 1:
			return *(s8 *)(table);
		case 2:
			return *(s16 *)(table);
		default:
			return *(s32 *)(table);
		}
	}
}

static u32 get_table_entry_size(u32 insn)
{
	unsigned char size = (insn >> 30) & ONES(2);

	switch (size) {
	case 0:
		return 1;
	case 1:
		return 2;
	default:
		return 4;
	}
}

static int add_possible_branch(struct objtool_file *file,
			       struct instruction *insn,
			       u32 base, s64 offset)
{
	struct instruction *dest_insn;
	struct alternative *alt;

	offset = base + 4 * offset;

	dest_insn = find_insn(file, insn->sec, offset);
	if (!dest_insn)
		return 0;

	alt = calloc(1, sizeof(*alt));
	if (!alt) {
		WARN("allocation failure, can't add jump alternative");
		return -1;
	}

	alt->insn = dest_insn;
	alt->skip_orig = true;
	list_add_tail(&alt->list, &insn->alts);
	return 0;
}

static struct switch_table_info *get_swt_info(struct section *swt_info_sec,
					      struct instruction *insn)
{
	u64 *table_ref;

	if (!insn->jump_table) {
		WARN("no jump table available for %s+0x%lx",
		     insn->sec->name, insn->offset);
		return NULL;
	}
	table_ref = (void *)(swt_info_sec->data->d_buf +
			     insn->jump_table->offset);
	return container_of(table_ref, struct switch_table_info,
			    switch_table_ref);
}

static int add_arm64_jump_table_dests(struct objtool_file *file,
				      struct instruction *insn)
{
	struct switch_table_info *swt_info;
	struct section *objtool_data;
	struct section *rodata_sec;
	struct section *branch_sec;
	struct instruction *pre_jump_insn;
	u8 *switch_table;
	u32 entry_size;

	objtool_data = find_section_by_name(file->elf,
					    ".discard.switch_table_info");
	if (!objtool_data)
		return 0;

	/*
	 * 1. Identify entry for the switch table
	 * 2. Retrieve branch instruction
	 * 3. Retrieve base offset
	 * 3. For all entries in switch table:
	 *     3.1. Compute new offset
	 *     3.2. Create alternative instruction
	 *     3.3. Add alt_instr to insn->alts list
	 */
	swt_info = get_swt_info(objtool_data, insn);

	/* retrieving pre jump instruction (ldr) */
	branch_sec = insn->sec;
	pre_jump_insn = find_insn(file, branch_sec,
				  insn->offset - 3 * sizeof(u32));
	entry_size = get_table_entry_size(*(u32 *)(branch_sec->data->d_buf +
						   pre_jump_insn->offset));

	/* retrieving switch table content */
	rodata_sec = find_section_by_name(file->elf, ".rodata");
	switch_table = (u8 *)(rodata_sec->data->d_buf +
			      insn->jump_table->addend);

	/*
	 * iterating over the pre-jumps instruction in order to
	 * retrieve switch base offset.
	 */
	while (pre_jump_insn && pre_jump_insn->offset <= insn->offset) {
		if (insn_is_adr_pcrel(pre_jump_insn)) {
			u64 base_offset;
			int i;

			base_offset = pre_jump_insn->offset +
				      pre_jump_insn->immediate;

			/*
			 * Once we have the switch table entry size
			 * we add every possible destination using
			 * alternatives of the original branch
			 * instruction
			 */
			for (i = 0; i < swt_info->nb_entries; i++) {
				s64 table_offset = next_offset(switch_table,
							       entry_size,
							       !swt_info->offset_unsigned);

				if (add_possible_branch(file, insn,
							base_offset,
							table_offset)) {
					return -1;
				}
				switch_table += entry_size;
			}
			break;
		}
		pre_jump_insn = next_insn_same_sec(file, pre_jump_insn);
	}

	return 0;
}

int arch_add_jump_table_dests(struct objtool_file *file,
			      struct instruction *insn)
{
	struct rela *table = insn->jump_table;

	if (table->c_jump_table)
		return get_insn_dests_from_rela_list_table(file, insn,
							   table);
	else
		return add_arm64_jump_table_dests(file, insn);
}

static struct rela *find_swt_info_jump_rela(struct section *swt_info_sec,
					    u32 index)
{
	u32 rela_offset;

	rela_offset = index * sizeof(struct switch_table_info) +
		      offsetof(struct switch_table_info, dyn_jump_ref);
	return find_rela_by_dest(swt_info_sec, rela_offset);
}

static struct rela *find_swt_info_table_rela(struct section *swt_info_sec,
					     u32 index)
{
	u32 rela_offset;

	rela_offset = index * sizeof(struct switch_table_info) +
		      offsetof(struct switch_table_info, switch_table_ref);
	return find_rela_by_dest(swt_info_sec, rela_offset);
}

/*
 * Aarch64 jump tables are just arrays of offsets (of varying size/signess)
 * representing the potential destination from a base address loaded by an adr
 * instruction.
 *
 * Aarch64 branches to jump tables are composed of multiple instructions:
 *
 *     ldr<?>  x_offset, [x_offsets_table, x_index, ...]
 *     adr     x_dest_base, <addr>
 *     add     x_dest, x_target_base, x_offset, ...
 *     br      x_dest
 *
 * The arm64_switch_table_detection_plugin will make the connection between
 * the instruction setting x_offsets_table (dyn_jump_ref) and the actual
 * table of offsets (switch_table_ref)
 */
struct rela *arch_find_switch_table(struct objtool_file *file,
				    struct instruction *insn)
{
	struct section *objtool_data;
	struct rela *res = NULL;
	u32 nb_swt_entries = 0;
	u32 i;

	objtool_data = find_section_by_name(file->elf,
					    ".discard.switch_table_info");
	if (objtool_data)
		nb_swt_entries = objtool_data->sh.sh_size /
				 sizeof(struct switch_table_info);

	for (i = 0; i < nb_swt_entries; i++) {
		struct rela *info_rela;

		info_rela = find_swt_info_jump_rela(objtool_data, i);
		if (info_rela && info_rela->sym->sec == insn->sec &&
		    info_rela->addend == insn->offset) {
			if (res) {
				WARN_FUNC("duplicate objtool_data rela",
					  info_rela->sec, info_rela->offset);
				continue;
			}
			res = find_swt_info_table_rela(objtool_data, i);
			if (!res)
				WARN_FUNC("missing relocation in objtool data",
					  info_rela->sec, info_rela->offset);
		}
	}

	/* Support C jump tables */
	if (!res) {
		struct rela *text_rela;

		text_rela = find_rela_by_dest_range(insn->sec, insn->offset,
						    insn->len);
		if (!text_rela || text_rela->sym->type != STT_SECTION ||
		    !text_rela->sym->sec->rodata ||
		    strcmp(text_rela->sym->sec->name, C_JUMP_TABLE_SECTION))
				return NULL;

		res = find_rela_by_dest(text_rela->sym->sec, text_rela->addend);
		if (res)
			res->c_jump_table = true;
	}

	return res;
}
