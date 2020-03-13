// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 Matt Helsley <mhelsley@vmware.com>
 */

#include <stdbool.h>
#include "../../check.h"

const char *objname;

int missing_check(const char *_objname, bool orc)
{
	return 127;
}

int __attribute__ ((weak, alias("missing_check"))) check(const char *_objname, bool orc);
