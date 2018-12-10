#define _GNU_SOURCE 1
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <getopt.h>

#include <signal.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/xattr.h>

/*
 * Change only one Kconfig variable each time which
 * can minimize rebuilding and simplify analyzing changes in output/test
 * results from one run to the next.
 *
 * Since we're iterating over a huge space of combinations we limit
 * ourselves to 32 Kconfig variables.
 *
 * Note that, since config variables are not always binary, we can test
 * more than 2^M combinations where M is the number of config vars. The
 * maximum number of config combinations we test is:
 * product(V_i) where V_i is the number of possible values config variable
 * i, for i in 1..M, can have.
 *
 * Hence to keep track of iteration counts we use 64 bits. This lets use use
 * the same tool whether we're configuring kernels or something much faster
 * to build and/or test.
 *
 */

static bool randomize = false;
static struct random_data random_state;

static void free_strings(char **s, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		free(s[i]);
	}
	free(s);
}

static int parse_strings(FILE *f, char ***result)
{
	int i = 0;
	char **strs = NULL, **nstrs;
	char *s;

	do {
		s = NULL;
		/* TODO handle config var vals with whitespace, etc */
		if (fscanf(f, "%*[ 	]%ms", &s) < 1 || !s)
			break;
		nstrs = realloc(strs, sizeof(*strs)*(i + 1));
		if (!nstrs && strs) {
			fprintf(stderr, "ERROR: Realloc failed (parsing variable values)\n");
			free(s);
			free_strings(strs, i);
			return -1;
		} else
			strs = nstrs;
		strs[i] = s;
		i++;
	} while(!feof(f));

	*result = strs;
	return i;
}

static void shuffle_strings(char **s, int n)
{
	int i, r;
	char *t;

	/* fisher-yates */
	for (i = n - 1; i > 0; i--) {
		if (random_r(&random_state, &r) != 0) {
			fprintf(stderr, "BUG random_r() failed unexpectedly\n");
			exit(EXIT_FAILURE);
		}
		r = r % (i + 1);
		t = s[i];
		s[i] = s[r];
		s[r] = t;
	}
}

static void dump_strings(char **s, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		fprintf(stderr, "%s%s", (i > 0) ? " " : "", s[i]);
	}
	fprintf(stderr, "\n");
}

struct config_var {
	char *name;
	char **values;
	int num_values;
	int next;
};

/*
 * Share this set of strings for tristates so that we don't have a horde of
 * pointers to length-1 strings.
 */
static char *ynm_values[3] = {
	"y",
	"n",
	"m",
};

static void clear_config_var(struct config_var *v)
{
	if (v->values && v->values != ynm_values)
		free_strings(v->values, v->num_values);
	free(v->name);
}

static void free_config_vars(struct config_var *vars, int n)
{
	int i;

	for (i = 0; i < n; i++)
		clear_config_var(&vars[i]);
	free(vars);
}

static int parse_config_var(FILE *f, const char *file_path, int file_line,
			    struct config_var *v)
{
	char *name = NULL;
	int num_values;

	v->name = NULL;
	v->values = NULL;
	v->num_values = 0;
	v->next = 0;

	if ((fscanf(f, " %ms", &name) < 1) || !name) {
		if (feof(f))
			return 0;
		fprintf(stderr, "ERROR: Failed to parse config variable at %s:%d\n",
			file_path, file_line);
		return -1;
	}
	v->name = name;

	num_values = parse_strings(f, &v->values);
	if (num_values < 0) {
		fprintf(stderr, "ERROR: %s:%d (%s)\n", file_path, file_line, name);
		return -1;
	}
	v->num_values = num_values;

	/* Share strings for tristate variables */
	if (!num_values || v->values == NULL) {
		v->values = ynm_values;
		v->num_values = 2;
	} else {
		if (v->num_values == 1 && !strcmp(v->values[0], "ynm")) {
			/*
			 * There's no good reason to set
			 * this so we use it as shorthand.
			 */
			free_strings(v->values, v->num_values);
			v->values = ynm_values;
			v->num_values = 3;
		}
	}

	/* Randomize walking the values for this variable */
	if (randomize && v->values && (v->values != ynm_values))
		shuffle_strings(v->values, v->num_values);

	fprintf(stderr, "%s[%d]: ", v->name, v->num_values);
	dump_strings(v->values, v->num_values);
	if (randomize) {
		if (random_r(&random_state, &v->next)) {
			fprintf(stderr, "BUG: random_r() failed unexpectedly\n");
			return -1;
		}
		v->next = v->next % v->num_values;
	}
	return 0;
}

static void usage(const char *prog, const char *reason)
{
	fprintf(stderr, "%s%sUsage: %s [-r [SEED]] [-s N] file1 ...\n\n"
"\t-r|--randomize\t\tSemi-randomly sample N configurations. See the note below.\n"
"\t-s N|--samples=N\tProduce N samples\n\n"
"Note: Rather than sample all possible configurations uniformly we provide some\n"
"useful guarantees. If we sample enough times then we guarantee that all variable\n"
"values have been set at least once. For example, if we have 5 variables and we\n"
"sample 10 configurations then we guarantee that each variable has changed at least\n"
"once. If we sample 20 configurations then each variable changes at least twice, and\n"
"so on. Contrast this withh a truly uniform random sampling which will often \"cluster\"\n"
"the sampled configs by varying a few variables and utterly ignoring others.\n\n",
		reason, reason ? "\n" : "", prog);
}

static const struct option opts[] = {
	{
		.name = "randomize",
		.has_arg = optional_argument,
		.flag = NULL,
		.val = 'r',
	},
	{
		.name = "samples",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 's',
	},
	{
		.name = NULL,
		.has_arg = 0,
		.flag = NULL,
		.val = 0,
	}
};
static const char *short_opts = "r::s:";


int main(int argc, char **argv)
{
	const char *initial_buf = "hit the any key";
	unsigned int initial_seed = 0xA2400C34;
	char *random_state_buf = strdup(initial_buf);
	const char *file_path;
	const char *prog;
	struct config_var *vars = NULL, *nvars;
	struct config_var *v;
	FILE *f = stdin;
	int i;
	int num_vars = 0, file_line;
	uint64_t max_iters = 1, num_samples = -1, j;
	int ex_code = EXIT_FAILURE;
	sigset_t die_signals, read_signals;

	prog = argv[0];
	if (argc < 2) {
		usage(prog, "ERROR: Missing command line arguments");
		goto cleanup;
	}

	while ((i = getopt_long(argc, argv, short_opts, opts, NULL)) != -1) {
		switch(i) {
		case 'r':
			randomize = true;
			random_state.state = NULL;

			if (fgetxattr(fileno(stdout), "user.config-sample.seed",
					&initial_seed, sizeof(initial_seed)) != sizeof(initial_seed)) {
				initial_seed = 0xA2400C34;
			}
			if (optarg && (sscanf(optarg, "%d", &initial_seed) < 1))
				continue;
			fprintf(stderr, "INFO: SEED=%d\n", initial_seed);
			initstate_r(initial_seed, random_state_buf,
					strlen(initial_buf) + 1, &random_state);
			fsetxattr(fileno(stdout), "user.config-sample.seed",
				  &initial_seed, sizeof(initial_seed), 0);
			break;
		case 's':
			if (sscanf(optarg, "%" PRIu64, &num_samples) < 1) {
				usage(prog, "ERROR: Could not parse number of samples");
				goto cleanup;
			}
			fprintf(stderr, "INFO: Generating %" PRIu64 " samples\n", num_samples);
			break;
		case ':':
			usage(prog, "ERROR: Missing argument");
			goto cleanup;
		default:
		case '?':
			usage(prog, "ERROR: Unknown option or extra argument");
			goto cleanup;
		}
	}

	argv = &argv[optind];
	argc -= optind;
	if (argc < 1) {
		usage(prog, "ERROR: Requires an input file or - for stdin");
		goto cleanup;
	}

	v = NULL;
	for (i = 0; i < argc; i++) {
		file_path = argv[i];
		if (!strcmp(file_path, "-"))
			f = stdin;
		else {
			f = fopen(file_path, "r");
			if (!f) {
				fprintf(stderr, "ERROR: Failed to read \"%s\"\n",
					file_path);
				goto cleanup;
			}
		}

		file_line = 0;
		do {
			if (v)
				goto already_allocd;
			nvars = realloc(vars, sizeof(*vars)*(num_vars + 1));
			if (!nvars) {
				fprintf(stderr, "ERROR: Realloc failed (parsing variables)\n");
				goto cleanup;
			}
			vars = nvars;
already_allocd:
			v = &vars[num_vars];
			if (parse_config_var(f, file_path, file_line, v))
				goto cleanup;
			if (v->name && v->num_values && v->values) {
				num_vars++;
				max_iters *= v->num_values;
			}
			file_line++;
			v = NULL;
		} while(!feof(f));

		if (f != stdin) {
			fclose(f);
			f = NULL;
		}
	}

	if (num_samples > max_iters) {
		fprintf(stderr, "INFO: %" PRIu64 " unique samples is smaller than number of requested samples %" PRIu64 ".\n", max_iters, num_samples);
		num_samples = max_iters;
	}
	if (max_iters > num_samples)
		max_iters = num_samples;

	/* NOTE: We could WARN here but that prevents a useful mode where we do
	 * one iteration per invocation of this command.
	 *
	 * if (max_iters < (num_vars << 1))
	 *	fprintf(stderr, "WARN: Low number of combinations\n");
	 */

	if (fgetxattr(fileno(stdout), "user.config-sample.j", &j, sizeof(j)) != sizeof(j)) {
		j = 0;
	} else {
		if (j >= max_iters) {
			fprintf(stderr, "INFO: Beginning previously-completed sample sequence\n");
			j = 0;
		} else {
			fprintf(stderr, "INFO: Resuming incomplete sample sequence\n");
			/* TODO adjust .next values of config variables to resume where
			 * we left off.
			 */
		}
	}

	/* Check for interruptions and save our place before exitting. */
	sigemptyset(&die_signals);
	sigaddset(&die_signals, SIGTERM);
	sigaddset(&die_signals, SIGHUP);
	sigaddset(&die_signals, SIGINT);
	sigprocmask(SIG_BLOCK, &die_signals, NULL);

	for (; j < max_iters; j++) {
		v = &vars[j % num_vars];

		/*
		 * Output the desired changes -- this works with other scripts
		 * and tools.
		 */
		printf("%s=%s\n", v->name, v->values[v->next]);
		v->next = (v->next + 1) % v->num_values;

		if (!sigpending(&read_signals)) {
			sigandset(&read_signals, &read_signals, &die_signals);
			if (!sigisemptyset(&read_signals)) {
				fsetxattr(fileno(stdout), "user.config-sample.j",
					  &j, sizeof(j), 0);
				fsync(fileno(stdout));

				/*
				 * Clear the pending die_signals and let them
				 * really kill us now.
				 */
				sigwait(&read_signals, &i);
				sigprocmask(SIG_UNBLOCK, &die_signals, NULL);
				break;
			}
		}
	}

	ex_code = EXIT_SUCCESS;
cleanup:
	free(random_state_buf);
	free_config_vars(vars, num_vars);
	if (f && (f != stdin))
		fclose(f);
	exit(ex_code);
}
