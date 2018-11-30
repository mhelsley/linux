/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2020 Matt Helsley <mhelsley@vmware.com>
 */

#ifndef _MCOUNT_H
#define _MCOUNT_H

#include <stdbool.h>
#include "objtool.h"

int missing_record_mcount(int argc, const char **argv);
int record_mcount(int argc, const char **argv);
#endif /* _MCOUNT_H */
