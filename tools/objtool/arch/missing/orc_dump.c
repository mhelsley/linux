// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#include "../../orc.h"

int missing_orc_dump(const char *_objname)
{
	return 127;
}

int __attribute__ ((weak, alias("missing_orc_dump"))) orc_dump(const char *_objname);
