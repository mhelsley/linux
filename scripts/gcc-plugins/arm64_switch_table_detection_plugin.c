// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include "gcc-common.h"

__visible int plugin_is_GPL_compatible;

static unsigned int arm64_switchtbl_rtl_execute(void)
{
	rtx_insn *insn;
	rtx_insn *labelp = NULL;
	rtx_jump_table_data *tablep = NULL;
	section *sec = get_section(".objtool_data", SECTION_STRINGS, NULL);
	section *curr_sec = current_function_section();

	for (insn = get_insns(); insn; insn = NEXT_INSN(insn)) {
		/*
		 * Find a tablejump_p INSN (using a dispatch table)
		 */
		if (!tablejump_p(insn, &labelp, &tablep))
			continue;

		if (labelp && tablep) {
			switch_to_section(sec);
			assemble_integer_with_op(".quad ", gen_rtx_LABEL_REF(Pmode, labelp));
			assemble_integer_with_op(".quad ", GEN_INT(GET_NUM_ELEM(tablep->get_labels())));
			assemble_integer_with_op(".quad ", GEN_INT(ADDR_DIFF_VEC_FLAGS(tablep).offset_unsigned));
			switch_to_section(curr_sec);
		}
	}
	return 0;
}

#define PASS_NAME arm64_switchtbl_rtl

#define NO_GATE
#include "gcc-generate-rtl-pass.h"

__visible int plugin_init(struct plugin_name_args *plugin_info,
			  struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	int tso = 0;
	int i;

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	PASS_INFO(arm64_switchtbl_rtl, "outof_cfglayout", 1,
		  PASS_POS_INSERT_AFTER);

	register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP,
			  NULL, &arm64_switchtbl_rtl_pass_info);

	return 0;
}
