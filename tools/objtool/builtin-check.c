// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2015-2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */

/*
 * objtool check:
 *
 * This command analyzes every .o file and ensures the validity of its stack
 * trace metadata.  It enforces a set of rules on asm code and C inline
 * assembly code so that stack traces can be reliable.
 *
 * For more information, see tools/objtool/Documentation/stack-validation.txt.
 */

#include <subcmd/parse-options.h>
#include "builtin.h"
#include "check.h"

bool no_fp, no_unreachable, retpoline, module, backtrace, uaccess;

struct saved_check_opts {
	bool no_fp, no_unreachable, retpoline, module, backtrace, uaccess;
};

static void *save_check_opts(void)
{
	struct saved_check_opts *o;

	o = malloc(sizeof(o));
	if (!o)
		return NULL;
	o->no_fp = no_fp;
	o->no_unreachable = no_unreachable;
	o->retpoline = retpoline;
	o->module = module;
	o->backtrace = backtrace;
	o->uaccess = uaccess;

	return o;
}

static void consume_check_opts(void *__o)
{
	struct saved_check_opts *o = __o;

	if (!o)
		return;
	no_fp = o->no_fp;
	no_unreachable = o->no_unreachable;
	retpoline = o->retpoline;
	module = o->module;
	backtrace = o->backtrace;
	uaccess = o->uaccess;

	free(o);

	return o;
}

static const char * const check_usage[] = {
	"objtool check [<options>] file.o",
	NULL,
};

static const struct option check_options[] = {
	OPT_BOOLEAN('f', "no-fp", &no_fp, "Skip frame pointer validation"),
	OPT_BOOLEAN('u', "no-unreachable", &no_unreachable, "Skip 'unreachable instruction' warnings"),
	OPT_BOOLEAN('r', "retpoline", &retpoline, "Validate retpoline assumptions"),
	OPT_BOOLEAN('m', "module", &module, "Indicates the object will be part of a kernel module"),
	OPT_BOOLEAN('b', "backtrace", &backtrace, "unwind on error"),
	OPT_BOOLEAN('a', "uaccess", &uaccess, "enable uaccess checking"),
	OPT_END(),
};

static int wrap_check(void *saved_opts, struct elf **elf)
{
	consume_check_opts(saved_opts);
	return check(objname, false);
}

const struct cmd_struct cmd_check = {
	.name = "check",
	.subcmds = CMD_SUBCMDS_NONE,
	.short_description = "Perform stack metadata validation on an object file",
	.options = check_options,
	.usage = check_usage,
	.may_write = false,
	.save_opts = save_check_opts,
	.fn = wrap_check,
};
