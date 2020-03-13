// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#include "../../orc.h"

int __attribute__ ((weak)) create_orc(struct objtool_file *file)
{
	return 127;
}

int __attribute__ ((weak)) create_orc_sections(struct objtool_file *file)
{
	return 127;
}
