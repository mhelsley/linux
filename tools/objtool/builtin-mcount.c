// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * objtool mcount:
 *
 * This command analyzes a .o file and constructs a table of the locations of
 * calls to 'mcount' useful to ftrace. We can optionally append this table to
 * the object file ("objtool mcount record foo.o") or output it separately
 * ("objtool mcount show"). The latter can be used to compare the expected
 * callers of mcount to those actually found.
 */

#include <string.h>
#include <subcmd/parse-options.h>
#include "builtin.h"

#include "mcount.h"

static const char * const mcount_usage[] = {
	"objtool mcount record [<options>] file.o [file2.o ...]",
	NULL,
};

bool warn_on_notrace_sect;

const static struct option mcount_options[] = {
	OPT_BOOLEAN('w', "warn-on-notrace-section", &warn_on_notrace_sect,
			"Emit a warning when a section omitting mcount "
			"(possibly due to \"notrace\" marking) is encountered"),
	OPT_END(),
};

bool is_cmd_mcount_available(void)
{
	return record_mcount != missing_record_mcount;
}

int cmd_mcount(int argc, const char **argv)
{
	argc--; argv++;
	if (argc <= 0)
		usage_with_options(mcount_usage, mcount_options);

	if (!strncmp(argv[0], "record", 6)) {
		argc = parse_options(argc, argv,
				     mcount_options, mcount_usage, 0);
		if (argc < 1)
			usage_with_options(mcount_usage, mcount_options);

		return record_mcount(argc, argv);
	}

	usage_with_options(mcount_usage, mcount_options);

	return 0;
}
