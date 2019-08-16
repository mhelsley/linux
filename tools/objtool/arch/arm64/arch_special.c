/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>

#include "../../special.h"
#include "../../warn.h"
#include "arch_special.h"
#include "bit_operations.h"
#include "insn_decode.h"

static u32 next_offset(u8 *table, u8 entry_size)
{
	switch (entry_size) {
	case 1:
		return table[0];
	case 2:
		return *(u16 *)(table);
	default:
		return *(u32 *)(table);
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
			       u32 base, u32 offset)
{
	struct instruction *dest_insn;
	struct alternative *alt;
	offset = base + 4 * offset;

	alt = calloc(1, sizeof(*alt));
	if (alt == NULL) {
		WARN("allocation failure, can't add jump alternative");
		return -1;
	}

	dest_insn = find_insn(file, insn->sec, offset);
	if (dest_insn == NULL) {
		free(alt);
		return 0;
	}
	alt->insn = dest_insn;
	alt->skip_orig = true;
	list_add_tail(&alt->list, &insn->alts);
	return 0;
}

int arch_add_jump_table(struct objtool_file *file, struct instruction *insn,
			struct rela *table, struct rela *next_table)
{
	struct rela *objtool_data_rela = NULL;
	struct switch_table_info *swt_info = NULL;
	struct section *objtool_data = find_section_by_name(file->elf, ".objtool_data");
	struct section *rodata_sec = find_section_by_name(file->elf, ".rodata");
	struct section *branch_sec = NULL;
	u8 *switch_table = NULL;
	u64 base_offset = 0;
	struct instruction *pre_jump_insn;
	u32 sec_size = 0;
	u32 entry_size = 0;
	u32 offset = 0;
	u32 i, j;

	if (objtool_data == NULL)
		return 0;

	/*
	 * 1. Using rela, Identify entry for the switch table
	 * 2. Retrieve base offset
	 * 3. Retrieve branch instruction
	 * 3. For all entries in switch table:
	 * 	3.1. Compute new offset
	 * 	3.2. Create alternative instruction
	 * 	3.3. Add alt_instr to insn->alts list
	 */
	sec_size = objtool_data->sh.sh_size;
	for (i = 0, swt_info = (void *)objtool_data->data->d_buf;
	     i < sec_size / sizeof(struct switch_table_info);
	     i++, swt_info++) {
		offset = i * sizeof(struct switch_table_info);
		objtool_data_rela = find_rela_by_dest_range(objtool_data, offset,
							    sizeof(u64));
		/* retrieving the objtool data of the switch table we need */
		if (objtool_data_rela == NULL ||
		    table->sym->sec != objtool_data_rela->sym->sec ||
		    table->addend != objtool_data_rela->addend)
			continue;

		/* retrieving switch table content */
		switch_table = (u8 *)(rodata_sec->data->d_buf + table->addend);

		/* retrieving pre jump instruction (ldr) */
		branch_sec = insn->sec;
		pre_jump_insn = find_insn(file, branch_sec,
					  insn->offset - 3 * sizeof(u32));
		entry_size = get_table_entry_size(*(u32 *)(branch_sec->data->d_buf + pre_jump_insn->offset));

		/*
		 * iterating over the pre-jumps instruction in order to
		 * retrieve switch base offset.
		 */
		while (pre_jump_insn != NULL &&
		       pre_jump_insn->offset <= insn->offset) {
			if (pre_jump_insn->stack_op.src.reg == ADR_SOURCE) {
				base_offset = pre_jump_insn->offset +
					      pre_jump_insn->immediate;
				/*
				 * Once we have the switch table entry size
				 * we add every possible destination using
				 * alternatives of the original branch
				 * instruction
				 */
				for (j = 0; j < swt_info->nb_entries; j++) {
					if (add_possible_branch(file, insn,
								base_offset,
								next_offset(switch_table, entry_size))) {
						return -1;
					}
					switch_table += entry_size;
				}
			}
			pre_jump_insn = next_insn_same_sec(file, pre_jump_insn);
		}
	}
	return 0;
}

struct rela *arch_find_switch_table(struct objtool_file *file,
				  struct rela *text_rela,
				  struct section *rodata_sec,
				  unsigned long table_offset)
{
	return text_rela;
}
