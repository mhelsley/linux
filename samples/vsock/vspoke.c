// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <getopt.h>

#include <readline/readline.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/vm_sockets.h>

#if 0
/* left compare aka startswith */
static int strlcmp(const char *src, const char *pat)
{
	size_t src_len = strlen(src);
	size_t pat_len = strlen(pat);

	return strncmp(src, pat, pat_len < src_len ? pat_len : src_len);
}
#endif

/* right compare aka endswith */
static int strrcmp(const char *src, const char *pat)
{
	size_t src_len = strlen(src);
	size_t pat_len = strlen(pat);

	if (pat_len > src_len)
		return -1;
	return strncmp(&src[src_len - pat_len], pat, pat_len);
}

/* left case compare aka startswith */
static int strlcasecmp(const char *src, const char *pat)
{
	size_t src_len = strlen(src);
	size_t pat_len = strlen(pat);

	return strncasecmp(src, pat, pat_len < src_len ? pat_len : src_len);
}

#if 0
/* right case compare aka endswith */
static int strrcasecmp(const char *src, const char *pat)
{
	size_t src_len = strlen(src);
	size_t pat_len = strlen(pat);

	if (pat_len > src_len)
		return -1;
	return strncasecmp(&src[src_len - pat_len], pat, pat_len);
}
#endif


#define DEFAULT_PORT 8080

static unsigned int local_cid = VMADDR_CID_RESERVED;

static struct sockaddr_vm dest_addr = {
	.svm_family = AF_VSOCK,
	.svm_port = DEFAULT_PORT,
	.svm_cid = VMADDR_CID_HOST,
};
static struct sockaddr_vm src_addr = {
	.svm_family = AF_VSOCK,
	.svm_port = VMADDR_PORT_ANY,
	.svm_cid = VMADDR_CID_ANY,
};
static bool is_server = false;
static bool is_stream = true;

static int sk = -1, lsk = -1; /* (accepted) socket and listen socket */

static int vsk_dgram_send(const char *buf, size_t len)
{
	if (send(sk, buf, len, MSG_EOR|MSG_NOSIGNAL) == len)
		return 0;
	perror("Failed to send datagram");
	return -1;
}

static int vsk_dgram_recv(char **buf, size_t *len)
{
	char _buf[256] = { 0, };
	size_t l = 0;

	l = recv(sk, _buf, 255, MSG_NOSIGNAL);
	if (l < 0) {
		perror("Failed to recv datagram");
		return -1;
	}
	_buf[l] = '\0';
	*buf = malloc(l);
	if (!*buf)
		return -1;
	memcpy(*buf, _buf, l);
	return 0;
}

static int vsk_stream_send(const char *buf, size_t len)
{
	if (send(sk, buf, len, MSG_EOR|MSG_NOSIGNAL) == len) {
		fprintf(stderr, "DEBUG: sent %zd bytes: \"%s\"\n", len, buf);
		return 0;
	}
	perror("Failed to send stream");
	return -1;
}

static int vsk_stream_recv(char **buf, size_t *len)
{
	char _buf[256] = { 0, };
	size_t l = 0;

	l = recv(sk, _buf, 255, MSG_NOSIGNAL);
	if (l < 0) {
		perror("Failed to recv stream");
		return -1;
	}
	_buf[l] = '\0';
	fprintf(stderr, "DEBUG: recvd %zd bytes: \"%s\"\n", l, _buf);
	*buf = malloc(l);
	if (!*buf)
		return -1;
	memcpy(*buf, _buf, l);
	return 0;
}

static int (*vsk_send)(const char *bytes, size_t len) = vsk_stream_send;
static int (*vsk_recv)(char **bytes, size_t *len) = vsk_stream_recv;

static const char *shortopts = "hscpd";
static const struct option longopts[] = {
	{
		.name = "help",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 'h',
	},

	/* Whether to wait for connections */
	{
		.name = "server",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 's',
	},
	{
		.name = "client",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 'c',
	},

	/* "flow" */
	{
		.name = "stream",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 'p',
	},
	{
		.name = "datagram",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 'd',
	},

	/* address bits */
	{
		.name = "src\0CID:PORT",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'S',
	},
	{
		.name = "src-cid\0CID",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'F',
	},
	{
		.name = "src-port\0PORT",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'f',
	},
	{
		.name = "dest\0CID:PORT",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'Q',
	},
	{
		.name = "dest-cid\0CID",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'T',
	},
	{
		.name = "dest-port\0PORT",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 't',
	},

	/* terminate */
	{
		.name = NULL,
		.has_arg = 0,
		.flag = NULL,
		.val = 0,
	}
};

static int get_local_cid(unsigned int *cid)
{
	int dev_vsock = open("/dev/vsock", O_RDONLY);
	int rc;

	if (dev_vsock < 0)
		return -1;
	rc = ioctl(dev_vsock, IOCTL_VM_SOCKETS_GET_LOCAL_CID, cid);
	close(dev_vsock);
	return rc;
}

static int parse_cid(const char *optarg, unsigned int *cid)
{
	int rc = 0;

	if (sscanf(optarg, "%u", cid) > 0)
		return rc;

	if (!strlcasecmp(optarg, "ANY"))
		*cid = VMADDR_CID_ANY;
	else if (!strlcasecmp(optarg, "HOST")) /* H... */
		*cid = VMADDR_CID_HOST;
	else if (!strlcasecmp(optarg, "HYVR") ||
		 !strlcasecmp(optarg, "HYPERVISOR")) /* HY... */
		*cid = VMADDR_CID_HYPERVISOR;
	else if (!strlcasecmp(optarg, "RSVD") ||
		 !strlcasecmp(optarg, "RESERVED"))
		*cid = VMADDR_CID_RESERVED;
	else if (!strlcasecmp(optarg, "LOCL") ||
		 !strlcasecmp(optarg, "LOCAL"))
		*cid = local_cid;
	else
		rc = -1;
	return rc;
}

static int parse_port(const char *optarg, unsigned int *port)
{
	int rc = 0;

	if (sscanf(optarg, "%u", port) > 0)
		return rc;

	if (!strlcasecmp(optarg, "ANY"))
		*port = VMADDR_PORT_ANY;
	else
		rc = -1;
	return rc;
}

static int parse_addr(char *optarg, struct sockaddr_vm *addr)
{
	char *s_cid, *s_port;
	int rc;

	memset(addr, 0, sizeof(*addr));
	addr->svm_family = AF_VSOCK;
	s_port = strchrnul(optarg, ':');
	if (*s_port != ':')
		return -1;
	*s_port = '\0';
	s_port++;
	s_cid = optarg;
	rc = parse_cid(s_cid, &addr->svm_cid);
	if (rc)
		return rc;
	return parse_port(s_port, &addr->svm_port);
}

/* Concatenating printf to a buffer
 * Returns >= 0 on success
 * Returns -1 on error
 * Returns -(n + 1) if the only error if n characters could not be concatenated
 */
#define scnprintf(str, len, fmt, ...) \
	 ({ \
		int ___rc = snprintf(str, len, fmt, ## __VA_ARGS__); \
		if (___rc < 0) { \
		} else if (___rc > len) { \
			str += len; \
			___rc = len - (___rc + 1); \
			len = 0; \
		} else { \
			str += ___rc; \
			len -= ___rc; \
		} \
		___rc; \
	})

static int snprint_vaddr(char *reply, size_t len,
			const struct sockaddr_vm *addr)
{
	int rc = -1;

	if (addr->svm_cid == VMADDR_CID_ANY)
		rc = scnprintf(reply, len, "ANY:");
	else if (addr->svm_cid == VMADDR_CID_HYPERVISOR)
		rc = scnprintf(reply, len, "HYVR:");
	else if (addr->svm_cid == VMADDR_CID_HOST)
		rc = scnprintf(reply, len, "HOST:");
	else if (addr->svm_cid == VMADDR_CID_RESERVED)
		rc = scnprintf(reply, len, "RSVD:");
	else if (addr->svm_cid == local_cid)
		rc = scnprintf(reply, len, "LOCL:");
	else
		rc = scnprintf(reply, len, "%u:", addr->svm_cid);
	if (rc < 2) /* need more than the : */
		goto out;

	if (addr->svm_port == VMADDR_PORT_ANY)
		rc = scnprintf(reply, len, "ANY");
	else
		rc = scnprintf(reply, len, "%u", addr->svm_port);

	if (rc > 0)
		rc = 0;
out:
	return rc;
}

static void print_help(const char *prog)
{
	char const * s;
	int i;

	printf("%s", prog);
	for (s = shortopts; *s; s++)
		printf(" [-%c]", *s);
	for (i = 0; longopts[i].name; i++) {
		s = longopts[i].name;
		printf(" [--%s", s);
		if (!longopts[i].flag && longopts[i].val && strchr(shortopts, longopts[i].val))
			printf("|-%c", longopts[i].val);
		s += strlen(s) + 1;
		switch (longopts[i].has_arg) {
		case required_argument: printf(" %s]", s); break;
		case optional_argument: printf(" [%s]]", s); break;
		case no_argument: printf("]"); break;
		default:
			printf("BUG in option help; unexpected value of has_arg");
			exit(EXIT_FAILURE);
			break;
		}
	}
	printf("\n");
}

static int parse_args(int argc, char * const argv[])
{
	int opt;
	int i;
	int rc = 0;

	while (!rc) {
		opt = getopt_long(argc, argv, shortopts, longopts, &i);
		if (opt == -1)
			break;
		switch (opt) {
		case 'h': print_help(argv[0]); exit(EXIT_SUCCESS); break;
		case 's': is_server = true; break;
		case 'c': is_server = false; break;
		case 'p': is_stream = true; break; /* p for pipe */
		case 'd': is_stream = false; break;
		case 'S': rc = parse_addr(optarg, &src_addr); break;
		case 'F': rc = parse_cid(optarg, &src_addr.svm_cid); break;
		case 'f': rc = parse_port(optarg, &src_addr.svm_port); break;
		case 'Q': rc = parse_addr(optarg, &dest_addr); break;
		case 'T': rc = parse_cid(optarg, &src_addr.svm_cid); break;
		case 't': rc = parse_port(optarg, &src_addr.svm_port); break;
		case '?':
			fprintf(stderr, "Unknown option \"%s\"\n",
				argv[optind]);
			rc = -1;
			break;
		case ':':
			fprintf(stderr, "Missing argument to --%s\n",
				longopts[i].name);
			rc = -1;
			break;
		default:
			fprintf(stderr, "BUG using getopt\n");
			exit(EXIT_FAILURE);
			break;
		}
	}
	return rc;
}

static int reset(void)
{
	struct sockaddr_vm vaddr;
	int socktype = SOCK_STREAM;
	socklen_t sz = sizeof(vaddr);
	int rc = 0;

	vsk_send = vsk_stream_send;
	vsk_recv = vsk_stream_recv;

	if (sk > -1) {
		rc = close(sk);
		sk = -1;
	}

	if (!is_stream) {
		socktype = SOCK_DGRAM;
		vsk_send = vsk_dgram_send;
		vsk_recv = vsk_dgram_recv;
	}

	rc = sk = socket(AF_VSOCK, socktype, 0);
	if (rc < 0) {
		rc = -errno;
		switch(rc) {
		case -EACCES:
		case -EADDRINUSE:
		case -EADDRNOTAVAIL:
		case -EINVAL:
		case -ENOPROTOOPT:
		case -ENOTCONN:
		case -EOPNOTSUPP:
		case -EPROTONOSUPPORT:
		case -ESOCKTNOSUPPORT:
			perror("Failed to open vsock");
		default:
			break;
		}
	} else
		rc = 0;
	if (rc)
		goto out;

	if (is_server) {
		char addr_str[256];

		sz = sizeof(vaddr);
		rc = getsockname(lsk, (struct sockaddr *)&vaddr, &sz);
		if (!rc) {
			snprint_vaddr(addr_str, 256, &vaddr);
			printf("initial address %s\n", addr_str);
		}

		lsk = sk;
		sk = -1;
		rc = bind(lsk, (struct sockaddr *)&src_addr, sizeof(src_addr));
		if (rc) {
			rc = -errno;
			perror("bind failed");
			goto out;
		}
		sz = sizeof(vaddr);
		rc = getsockname(lsk, (struct sockaddr *)&vaddr, &sz);
		if (!rc) {
			snprint_vaddr(addr_str, 256, &vaddr);
			printf("bound to %s\n", addr_str);
		}

		rc = listen(lsk, 2);
		if (rc) {
			rc = -errno;
			perror("listen failed");
			goto out;
		}
	} else {
		rc = connect(sk, (struct sockaddr *)&dest_addr,
				sizeof(dest_addr));
		if (rc) {
			rc = -errno;
			perror("connect failed");
			goto out;
		}
	}
out:
	return rc;
}

static int reply_ok_vaddr(char *reply, size_t len,
			  const struct sockaddr_vm *addr)
{
	int rc = -1;

	scnprintf(reply, len, "ok ");
	snprint_vaddr(reply, len, addr);
	rc = 0;

	return rc;
}

static int parse_input(const char *cmd)
{
	char reply[256];
	int rc = -1;
	int p = 0;

	snprintf(reply, 256, "err \"%s\"", cmd);
	if (!strncmp(&cmd[p], "show ", 5)) {
		p += 5;
		if (!strncmp(&cmd[p], "addr ", 5)) {
			p += 5;
			if (!strcmp(&cmd[p], "local")) {
				if (local_cid != VMADDR_CID_RESERVED)
					snprintf(reply, 256, "ok %u", local_cid);
			} else if (!strcmp(&cmd[p], "src")) {
				rc = reply_ok_vaddr(reply, 256, &src_addr);
			} else if (!strcmp(&cmd[p], "dest")) {
				rc = reply_ok_vaddr(reply, 256, &dest_addr);
			} else if (!strcmp(&cmd[p], "sock")) {
				struct sockaddr_vm sock_addr;
				socklen_t sz = sizeof(sock_addr);

				rc = getsockname(sk,
						(struct sockaddr *)&sock_addr,
						&sz);
				if (rc)
					goto out;
				rc = reply_ok_vaddr(reply, 256, &sock_addr);
			} else if (!strcmp(&cmd[p], "peer")) {
				struct sockaddr_vm peer_addr;
				socklen_t sz = sizeof(peer_addr);

				rc = getpeername(sk,
						(struct sockaddr *)&peer_addr,
						&sz);
				if (rc)
					goto out;
				rc = reply_ok_vaddr(reply, 256, &peer_addr);
			} else if (!strcmp(&cmd[p], "ANY")) {
				struct sockaddr_vm const_addr =  {
					.svm_family = AF_VSOCK,
					.svm_port = VMADDR_PORT_ANY,
					.svm_cid = VMADDR_CID_ANY,
				};
				rc = reply_ok_vaddr(reply, 256, &const_addr);
			} else if (!strcmp(&cmd[p], "HOST")) {
				struct sockaddr_vm const_addr =  {
					.svm_family = AF_VSOCK,
					.svm_port = VMADDR_PORT_ANY,
					.svm_cid = VMADDR_CID_HOST,
				};
				rc = reply_ok_vaddr(reply, 256, &const_addr);
			} else if (!strcmp(&cmd[p], "HYPER")) {
				struct sockaddr_vm const_addr =  {
					.svm_family = AF_VSOCK,
					.svm_port = VMADDR_PORT_ANY,
					.svm_cid = VMADDR_CID_HYPERVISOR,
				};
				rc = reply_ok_vaddr(reply, 256, &const_addr);
			} else if (!strcmp(&cmd[p], "RSVD")) {
				struct sockaddr_vm const_addr =  {
					.svm_family = AF_VSOCK,
					.svm_port = VMADDR_PORT_ANY,
					.svm_cid = VMADDR_CID_RESERVED,
				};
				rc = reply_ok_vaddr(reply, 256, &const_addr);
			} else {
				goto out;
			}
		/* } else if (!strncmp(&cmd[p], "", )) {*/
		} else {
			goto out;
		}
	} else if (!strncmp(cmd, "echo ", 5)) {
		p += 5;
		/* Can echo lines up to 250 chars long */
		snprintf(reply, 256, "ok %s", &cmd[p]);
		rc = 0;
#if 0
	} else if (!strcmp(cmd, "shell")) {
		struct passwd *e;
		p += 5;
		rc = dup2(sk, 0);
		rc = dup2(sk, 1);
		rc = dup2(sk, 2);
		e = getpwent();
		if (!e)
			goto out;
		if (e->pw_dir)
			rc = chdir(e->pw_dir);
		else
			rc = chdir("/tmp");
		rc = close(sk);
		execv(e->pw_shell)
#endif
	} else if (!strcmp(cmd, "reset")) {
		rc = reset();
		if (!rc) snprintf(reply, 256, "ok");
	} else if (!strcmp(cmd, "exit") || !strcmp(cmd, "close") || \
		   !strcmp(cmd, "quit")) {
		rc = close(sk);
		sk = -1;
		if (!rc) {
			snprintf(reply, 256, "ok");
			rc = 0;
		}
	} else if (!strncmp(cmd, "set ", 4)) {
		p += 4;
		if (!strncmp(&cmd[p], "endpoint ", 9)) {
			p += 9;
			if (!strcmp(&cmd[p], "server")) {
				is_server = true;
			} else if (!strcmp(&cmd[p], "client")) {
				is_server = false;
			} else {
				goto out;
			}
		} else if (!strncmp(&cmd[p], "flow ", 5)) {
			p += 5;
			if (!strcmp(&cmd[p], "stream")) {
				is_stream = true;
			} else if (!strcmp(&cmd[p], "datagram")) {
				is_stream = false;
			} else {
				goto out;
			}
		} else {
			goto out;
		}
		snprintf(reply, 256, "ok");
		rc = 0;
	} else if (!strncmp(cmd, "get ", 4)) {
		p += 4;
		if (!strcmp(&cmd[p], "endpoint")) {
			snprintf(reply, 256, "ok %s", is_server ? "server" : "client");
		} else if (!strcmp(&cmd[p], "flow")) {
			snprintf(reply, 256, "ok %s", is_stream ? "stream" : "datagram");
		} else {
			goto out;
		}
	} else {
		fprintf(stderr, "Unrecognized command \"%s\"", cmd);
	}
out:
	if (!rc)
		rc = vsk_send(reply, strlen(reply));
	else
		vsk_send(reply, strlen(reply));
	return rc;
}

/* ignore lines sort of like a shell */
static bool ignore(const char *input)
{
	while (input[0]) {
		if (input[0] <= ' ')
			input++;
		else
			break;
	}
	return input[0] == '\0' || input[0] == '#';
}

int main (int argc, char * const argv[])
{
	char *input = NULL;
	size_t input_len;
	char *prompt;
	int rc;

	/* Have to do this before parsing command line args */
	rc = get_local_cid(&local_cid);
	if (!rc)
		printf("Local CID: %u\n", local_cid);
	prompt = getenv("PS2");
	if (!prompt || !strlen(prompt))
		prompt = "> ";

	/* If the executable name ends with these then set defaults */
	if (!strrcmp(argv[0], "server"))
		is_server = true;
	if (!strrcmp(argv[0], "client"))
		is_server = false;

	if (parse_args(argc, argv))
		return 1;
	if (reset())
		return EXIT_FAILURE;
	rc = EXIT_SUCCESS;
	while ((rc == EXIT_SUCCESS) && ((lsk > -1) || (sk > -1))) {
		if (is_server) {
			struct sockaddr_vm vaddr;
			char addr_str[256];
			socklen_t sz;

			sz = sizeof(vaddr);
			if (sk == -1) {
				sk = accept(lsk, (struct sockaddr *)&vaddr,
						&sz);
				if (sk < -1)
					continue;
				snprint_vaddr(addr_str, 256, &vaddr);
				addr_str[255] = 0;
				printf("%s accepted on ", addr_str);

				sz = sizeof(vaddr);
				rc = getsockname(lsk, (struct sockaddr *)&vaddr, &sz);
				snprint_vaddr(addr_str, 256, &vaddr);
				addr_str[255] = 0;
				printf("%s\n", addr_str);

				sz = sizeof(vaddr);
				rc = getpeername(sk, (struct sockaddr *)&vaddr, &sz);
				snprint_vaddr(addr_str, 256, &vaddr);
				addr_str[255] = 0;
				printf("peer %s connected to local ", addr_str);

				sz = sizeof(vaddr);
				rc = getsockname(sk, (struct sockaddr *)&vaddr, &sz);
				snprint_vaddr(addr_str, 256, &vaddr);
				addr_str[255] = 0;
				printf("%s\n", addr_str);
			}

			rc = vsk_recv(&input, &input_len);
			if (rc || input_len < 1) {
				rc = EXIT_SUCCESS;
				continue; /* TODO reset ? */
			}
			rc = parse_input(input);
			if (rc) {
				if (errno == EPIPE) {
					close(sk);
					sk = -1;
					rc = EXIT_SUCCESS;
					continue;
				}
				rc = EXIT_SUCCESS;
				continue; /* TODO reset ? */
			}
		} else {
			input = readline(prompt);
			fprintf(stderr, "DEBUG: input from readline: \"%s\"\n", input);
			if (!input /* ctrl-d */ ||
			    !strcmp(input, "exit") ||
			    !strcmp(input, "quit") ||
			    !strcmp(input, "close")) {
				fprintf(stderr, "DEBUG: exiting\n");
				if (!input)
					vsk_send("exit", strlen("exit"));
				else {
					vsk_send(input, strlen(input));
					free(input);
				}
				close(sk);
				sk = -1;
				rc = EXIT_SUCCESS;
				break;
			}
			if (ignore(input)) {
				fprintf(stderr, "DEBUG: ignoring input \"%s\"\n", input);
				free(input);
				continue;
			}

			fprintf(stderr, "DEBUG: sending input\n");
			rc = vsk_send(input, strlen(input));
			free(input);
			if (rc) {
				rc = EXIT_SUCCESS;
				continue; /* TODO reset ? */
			}
			fprintf(stderr, "DEBUG: receiving response\n");
			rc = vsk_recv(&input, &input_len);
			if (rc || !input) {
				rc = EXIT_SUCCESS;
				continue; /* TODO reset ? */
			}
			if (ignore(input)) {
				fprintf(stderr, "DEBUG: ignoring result \"%s\"\n", input);
				free(input);
				continue;
			}
			printf("%s\n", input);
			if (!strncmp(input, "err", 3))
				rc = EXIT_FAILURE;
			free(input);
		}
		break;
	}
	return rc;
}
