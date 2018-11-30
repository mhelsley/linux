// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 Matt Helsley <mhelsley@vmware.com>
 */

#include <stdbool.h>
#include "../../mcount.h"

const char *objname;

int missing_record_mcount(int argc, const char **argv)
{
	return 127;
}

int __attribute__ ((weak, alias("missing_record_mcount"))) record_mcount(int argc, const char **argv);
