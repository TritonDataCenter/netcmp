/*
 * netcmp.c: compare TCP connections reported by netstat to identify connections
 * abandoned by one side but not the other.  Invoke as:
 *
 *     netcmp [-d] FILE1 FILE2 ...
 *
 * where each of the named files contains the output of
 * "netstat -n -f inet -P tcp" from one system.
 *
 * TODO current status: This does produce a somewhat useful report, but the
 * summary is still pretty unwieldy.  It would be great if this produced a
 * report that said:
 *
 *     o for every pair of IP addresses for which we have data, and with at
 *       least one connection between them:
 *
 *           o the names of the source data files
 *
 *           o a count of connections between them that are known on both sides,
 *             with a fixed number of examples (e.g., 5)
 *
 *           o a count of connections between them that are _not_ known on both
 *             sides, with a fixed number of examples (e.g., 5)
 *
 *     o for every pair of IP addresses where we have data for only one of them
 *       and a connection between them:
 *
 *           o the name of the source data file
 *
 *           o a count of connections between them, with a fixed number of
 *             examples
 *
 *     o a count of connections with more than two sources, with a fixed number
 *       of examples (e.g., 5)
 */

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/avl.h>
#include <unistd.h>

#define EXIT_USAGE 2

/*
 * There's not a great way to use the illumos-provided boolean_t in a portable
 * way, so we just define our own.
 */
typedef enum {
	NB_FALSE = 0,
	NB_TRUE  = 1
} ncbool_t;

/*
 * String buffer sizes for storing an IPv4 address, a TCP port, and the
 * combination.  The calculation for both of them needs to include the colon
 * separator, but not two NULL terminators, so it's just the sum of the first
 * two.
 */
#define	IPV4_STRBUFSZ	(sizeof ("000.000.000.000"))
#define	TCP_PORTBUFSZ	(sizeof ("65536"))
#define	IPV4PORT_BUFSZ	(sizeof ("000.000.000.000:12345"))

/*
 * Represents an input file, which corresponds to the netstat output from a
 * single host.  The host is identified by the basename of the input filename.
 * We track hosts that we've got data for so that we can distinguish cases where
 * there's an abandoned connection (i.e., when there's a connection from A to B
 * and we believe we have data for both A and B) and an external connection
 * (i.e., when we have no data for A or B).
 *
 * We track a set of these in an AVL tree indexed by the local IP address.
 * (There can be more than one of these per input file when hosts have more
 * than one local IP address.)
 */
typedef struct {
	char		ncs_ip[IPV4_STRBUFSZ];	/* source IP address */
	char		ncs_label[128];		/* source label */
	avl_node_t	ncs_link;		/* link in AVL tree */
} ncsource_t;

/*
 * This structure keeps track of each unique four-tuple: local and remote IP
 * addresses and TCP ports.  We're not going to do any network operations with
 * these, so we don't bother convering them to network byte order.  The only
 * reason we even parse the port numbers is to save a few bytes.  (We may end up
 * processing millions of connections.)  We could save more memory and
 * potentially operate faster by parsing the IP addresses, too.
 *
 * In the best case, we're going to wind up seeing the same four-tuple twice:
 * once when we process the netstat output for each endpoint.  We normalize the
 * structure by sorting the (IP/port) pairs and putting the first one into
 * ncc_ip1/ncc_port1 and the second one into ncc_ip2/ncc_port2.
 */
typedef struct {
	char		ncc_ip1[IPV4_STRBUFSZ];	/* first IP/port tuple */
	uint16_t	ncc_port1;
	char		ncc_ip2[IPV4_STRBUFSZ];	/* second IP/port tuple */
	uint16_t	ncc_port2;

	/* This could be turned into an enum to save memory. */
	char		ncc_state[16];		/* TCP connection state */

	/*
	 * In general, we expect no more than two sources.  We'll count up to
	 * UINT8_MAX sources, but only track two of them.
	 */
	uint8_t		ncc_nsources;		/* number of sources */
	ncsource_t	*ncc_sources[2];	/* first two soures */

	avl_node_t	ncc_conn_link;		/* link in AVL tree */
} ncconn_t;

/*
 * Represents the overall netcmp operation.  Configuration, counters, and
 * accumulated state hang off this object.
 */
typedef struct {
	/* enable debug messages */
	ncbool_t	nc_debug;

	/* count of localhost connections skipped */
	unsigned long	nc_nlocalhost;

	/* set of all connections found */
	avl_tree_t	nc_conns;

	/* set of all sources found */
	avl_tree_t	nc_sources;
} netcmp_t;

static const char *nc_arg0;
static void usage(void);

/* Public functions (if this were a separate module) */
static void nc_init(netcmp_t *);
static int nc_parse_options(netcmp_t *, int, char *[]);
static int nc_read_file(netcmp_t *, const char *);
static void nc_report(netcmp_t *);
static void nc_ipport_tostr(char *, size_t, const char *, uint16_t);
static void nc_conn_dump(FILE *, ncconn_t *);

/* Private functions */
static int nc_parse_row(netcmp_t *, const char *, char *);
static int nc_parse_ipport(char *, size_t, uint16_t *, char *);
static int nc_conn_compare(const void *, const void *);
static int nc_source_compare(const void *vncs1, const void *vncs2);

int
main(int argc, char *argv[])
{
	int i;
	netcmp_t netcmp;

	nc_arg0 = argv[0];
	nc_init(&netcmp);
	i = nc_parse_options(&netcmp, argc, argv);
	assert(i >= 0);

	if (argc - optind < 2) {
		warnx("need two filenames");
		usage();
	}

	while (i < argc) {
		assert(argv[i] != NULL);
		if (nc_read_file(&netcmp, argv[i++]) != 0)
			return (EXIT_FAILURE);
	}

	nc_report(&netcmp);
	return (0);
}

static void
usage(void)
{
	(void) fprintf(stderr, "usage: %s [-d] FILE1 FILE2 ...\n", nc_arg0);
	exit(EXIT_USAGE);
}

/*
 * netcmp "public" functions (if this were a separate module)
 */

/*
 * Initialize the netcmp operation.
 */
static void
nc_init(netcmp_t *ncp)
{
	bzero(ncp, sizeof (*ncp));
	avl_create(&ncp->nc_conns, nc_conn_compare,
	    sizeof (ncconn_t), offsetof(ncconn_t, ncc_conn_link));
	avl_create(&ncp->nc_sources, nc_source_compare,
	    sizeof (ncsource_t), offsetof(ncsource_t, ncs_link));
}

/*
 * Parse command-line options, recording the requested configuration into "ncp".
 */
static int
nc_parse_options(netcmp_t *ncp, int argc, char *argv[])
{
	char c;

	while ((c = getopt(argc, argv, ":d")) != -1) {
		switch (c) {
		case 'd':
			ncp->nc_debug = NB_TRUE;
			break;

		case ':':
			warnx("option requires an argument: -%c", c);
			usage();
			break;

		case '?':
			warnx("unrecognized option: -%c", c);
			usage();
			break;
		}
	}

	return (optind);
}

/*
 * Read the netstat data contained in the named file and record what we find.
 */
static int
nc_read_file(netcmp_t *ncp, const char *filename)
{
	FILE *fstream;
	const char *source;
	char buf[256];
	int i;
	int linenum = 1;

	(void) fprintf(stderr, "processing file %s\n", filename);
	if ((fstream = fopen(filename, "r")) == NULL) {
		err(EXIT_FAILURE, "fopen");
	}

	/* Check the first line. */
	if (fgets(buf, sizeof (buf), fstream) == NULL) {
		errx(EXIT_FAILURE, "reading from stream");
	}

	if (strcmp(buf, "\n") != 0) {
		errx(EXIT_FAILURE, "expected blank line");
	}

	/* Check the second line. */
	linenum++;
	if (fgets(buf, sizeof (buf), fstream) == NULL) {
		errx(EXIT_FAILURE, "reading from stream");
	}

	if (strcmp(buf, "TCP: IPv4\n") != 0) {
		errx(EXIT_FAILURE, "expected \"TCP: IPv4\" header");
	}

	/* Check the third line. */
	linenum++;
	if (fgets(buf, sizeof (buf), fstream) == NULL) {
		errx(EXIT_FAILURE, "reading from stream");
	}

	if (strstr(buf, "Local Address") == NULL ||
	    strstr(buf, "Remote Address") == NULL ||
	    strstr(buf, "Swind") == NULL || strstr(buf, "Send-Q") == NULL ||
	    strstr(buf, "Rwind") == NULL || strstr(buf, "Recv-Q") == NULL ||
	    strstr(buf, "State") == NULL || strchr(buf, '\n') == NULL) {
		errx(EXIT_FAILURE, "expected column headers");
	}

	/* Check the fourth line. */
	linenum++;
	if (fgets(buf, sizeof (buf), fstream) == NULL) {
		errx(EXIT_FAILURE, "reading from stream");
	}

	for (i = 0; buf[i] != '\0' && buf[i] != '\n'; i++) {
		if (buf[i] != '-' && !isspace(buf[i])) {
			errx(EXIT_FAILURE, "expected separator row");
		}
	}

	/* The remaining lines are data lines. */
	source = strrchr(filename, '/');
	if (source == NULL) {
		source = filename;
	} else {
		source = source + 1;
	}

	while (fgets(buf, sizeof (buf), fstream) != NULL) {
		linenum++;

		if (strcmp(buf, "\n") == 0) {
			continue;
		}

		if (strchr(buf, '\n') == NULL) {
			errx(EXIT_FAILURE, "line too long");
		}

		if (nc_parse_row(ncp, source, buf) != 0) {
			errx(EXIT_FAILURE,
			    "failed to process line %d", linenum);
		}
	}

	(void) fclose(fstream);
	return (0);
}

/*
 * Dump to stdout a final report -- the actual "netcmp" output.
 */
static void
nc_report(netcmp_t *ncp)
{
	ncconn_t *ncc;
	ncconn_t *ncc_error;
	ncsource_t source;
	boolean_t external;
	int nsymmetric = 0;
	int nasymmetric = 0;
	int nexternal = 0;
	int nerror = 0;
	int ntimewait = 0;
	char buf1[IPV4PORT_BUFSZ];
	char buf2[IPV4PORT_BUFSZ];

	for (ncc = avl_first(&ncp->nc_conns); ncc != NULL;
	    ncc = AVL_NEXT(&ncp->nc_conns, ncc)) {
		if (strcmp(ncc->ncc_state, "TIME_WAIT") == 0) {
			ntimewait++;
			continue;
		}

		if (ncc->ncc_nsources > 2) {
			if (ncp->nc_debug) {
				(void) fprintf(stderr, "found connection "
				    "with more than two sources:\n");
				nc_conn_dump(stderr, ncc);
			}

			ncc_error = ncc;
			nerror++;
			continue;
		}

		if (ncc->ncc_nsources == 2) {
			nsymmetric++;
			continue;
		}

		assert(ncc->ncc_nsources == 1);
		bzero(&source, sizeof (source));
		(void) strlcpy(source.ncs_ip, ncc->ncc_ip1,
		    sizeof (source.ncs_ip));
		external = avl_find(&ncp->nc_sources, &source, NULL) == NULL;
		if (!external) {
			(void) strlcpy(source.ncs_ip, ncc->ncc_ip2,
			    sizeof (source.ncs_ip));
			external = avl_find(
			    &ncp->nc_sources, &source, NULL) == NULL;
		}

		if (external) {
			if (ncp->nc_debug) {
				(void) fprintf(stderr, "found connection "
				    "involving IP for which we have no "
				    "data:\n");
				nc_conn_dump(stderr, ncc);
			}

			nexternal++;
			continue;
		}

		nasymmetric++;
		nc_ipport_tostr(buf1, sizeof (buf1), ncc->ncc_ip1,
		    ncc->ncc_port1);
		nc_ipport_tostr(buf2, sizeof (buf2), ncc->ncc_ip2,
		    ncc->ncc_port2);
		(void) fprintf(stdout, "%21s <-> %21s only in %s\n",
		    buf1, buf2, ncc->ncc_sources[0]->ncs_label);
	}

	if (nerror != 0) {
		warnx("%d connection%s had more than two sources! example:\n",
		    nerror, nerror == 1 ? "" : "s");
		nc_conn_dump(stderr, ncc_error);
	}

	(void) printf("summary of connections found:\n");
	(void) printf("    %7lu localhost connections skipped\n",
	    ncp->nc_nlocalhost);
	(void) printf("    %7d pruned (in state TIME_WAIT)\n", ntimewait);
	(void) printf("    %7d symmetric (present on both sides)\n",
	    nsymmetric);
	(void) printf("    %7d external (only one side's data was supplied)\n",
	    nexternal);
	(void) printf("    %7d asymmetric (abandoned by one side)\n",
	    nasymmetric);
}

/*
 * Dump all information we have about one of the connections.  This is intended
 * for "verbose" mode.
 */
static void
nc_conn_dump(FILE *stream, ncconn_t *ncc)
{
	int i;
	char buf1[IPV4PORT_BUFSZ];
	char buf2[IPV4PORT_BUFSZ];

	nc_ipport_tostr(buf1, sizeof (buf1), ncc->ncc_ip1, ncc->ncc_port1);
	nc_ipport_tostr(buf2, sizeof (buf2), ncc->ncc_ip2, ncc->ncc_port2);

	(void) fprintf(stream, "    %21s <-> %21s\n", buf1, buf2);
	for (i = 0; i < ncc->ncc_nsources && i < 2; i++) {
		fprintf(stream, "        source: %s\n",
		    ncc->ncc_sources[i]->ncs_label);
	}
}

/*
 * Writes into "buf" a string representation of the given IPv4 address and port.
 * This NULL-terminates as long as bufsz > 0, and the string will be complete as
 * long as bufsz > IPV4PORT_BUFSZ.
 */
static void
nc_ipport_tostr(char *buf, size_t bufsz, const char *ip, uint16_t port)
{
	(void) snprintf(buf, bufsz, "%s:%d", ip, port);
}


/*
 * Private functions
 */

/*
 * Parse a single line of netstat output.  "line" is guaranteed to be
 * NULL-terminated and to have a newline character at the end of it.  This
 * function may modify the string arbitrarily.
 */
static int
nc_parse_row(netcmp_t *ncp, const char *source, char *line)
{
	ncconn_t *ncc, *oncc;
	ncsource_t *ncs, *oncs;
	char *ipport1, *ipport2, *ign, *state, *lasts, *nl;
	int cmp;
	char tmpstr[IPV4_STRBUFSZ];
	uint16_t tmpport;
	avl_index_t avlwhere;

	ipport2 = NULL;
	ign = NULL;
	state = NULL;

	ipport1 = strtok_r(line, " ", &lasts);
	if (ipport1 != NULL)
		ipport2 = strtok_r(NULL, " ", &lasts);
	if (ipport2 != NULL)
		/* "Swind" is currently ignored. */
		ign = strtok_r(NULL, " ", &lasts);
	if (ign != NULL)
		/* "Send-Q" is currently ignored. */
		ign = strtok_r(NULL, " ", &lasts);
	if (ign != NULL)
		/* "Rwind" is currently ignored. */
		ign = strtok_r(NULL, " ", &lasts);
	if (ign != NULL)
		/* "Recv-Q" is currently ignored. */
		ign = strtok_r(NULL, " ", &lasts);
	if (ign != NULL)
		state = strtok_r(NULL, " ", &lasts);

	if (ipport1 == NULL || ipport2 == NULL || state == NULL) {
		warnx("failed to parse line");
		return (-1);
	}

	nl = strchr(state, '\n');
	assert(nl != NULL);
	*nl = '\0';

	if (strcmp(state, "CLOSED") != 0 &&
	    strcmp(state, "IDLE") != 0 &&
	    strcmp(state, "BOUND") != 0 &&
	    strcmp(state, "LISTEN") != 0 &&
	    strcmp(state, "SYN_SENT") != 0 &&
	    strcmp(state, "SYN_RCVD") != 0 &&
	    strcmp(state, "ESTABLISHED") != 0 &&
	    strcmp(state, "CLOSE_WAIT") != 0 &&
	    strcmp(state, "FIN_WAIT_1") != 0 &&
	    strcmp(state, "CLOSING") != 0 &&
	    strcmp(state, "LAST_ACK") != 0 &&
	    strcmp(state, "FIN_WAIT_2") != 0 &&
	    strcmp(state, "TIME_WAIT") != 0) {
		warnx("unexpected TCP state: \"%s\"", state);
		return (-1);
	}

	if ((ncc = calloc(sizeof (*ncc), 1)) == NULL ||
	    (ncs = calloc(sizeof (*ncs), 1)) == NULL) {
		warn("calloc");
		free(ncc);
		return (-1);
	}

	if (nc_parse_ipport(ncc->ncc_ip1, sizeof (ncc->ncc_ip1),
	    &ncc->ncc_port1, ipport1) != 0 ||
	    nc_parse_ipport(ncc->ncc_ip2, sizeof (ncc->ncc_ip2),
	    &ncc->ncc_port2, ipport2) != 0) {
		free(ncc);
		free(ncs);
		return (-1);
	}

	/*
	 * Ignore connections over 127.0.0.1.  Our methodology assumes IPs are
	 * unique across all input, which isn't the case here.  That's okay,
	 * because it's pretty unlikely there would be an asymmetry over
	 * localhost.
	 */
	if (strcmp(ncc->ncc_ip1, "127.0.0.1") == 0 ||
	    strcmp(ncc->ncc_ip2, "127.0.0.1") == 0) {
		ncp->nc_nlocalhost++;
		free(ncc);
		free(ncs);
		return (0);
	}

	/*
	 * Make sure that we have a source record based on the local IP address.
	 */
	(void) strlcpy(ncs->ncs_ip, ncc->ncc_ip1, sizeof (ncs->ncs_ip));
	oncs = avl_find(&ncp->nc_sources, ncs, &avlwhere);
	if (oncs == NULL) {
		(void) strlcpy(ncs->ncs_label, source,
		    sizeof (ncs->ncs_label));
		avl_insert(&ncp->nc_sources, ncs, avlwhere);
	} else {
		free(ncs);
		ncs = oncs;
	}

	/*
	 * Sort the two (IP, port) tuples within the ncconn_t to normalize the
	 * connection identifier.
	 */
	cmp = strcmp(ncc->ncc_ip1, ncc->ncc_ip2);
	if (cmp > 0 || (cmp == 0 && ncc->ncc_port1 > ncc->ncc_port2)) {
		tmpport = ncc->ncc_port1;
		ncc->ncc_port1 = ncc->ncc_port2;
		ncc->ncc_port2 = tmpport;

		(void) strlcpy(tmpstr, ncc->ncc_ip1, sizeof (tmpstr));
		(void) strlcpy(ncc->ncc_ip1, ncc->ncc_ip2,
		    sizeof (ncc->ncc_ip1));
		(void) strlcpy(ncc->ncc_ip2, tmpstr, sizeof (ncc->ncc_ip2));
	}

	/*
	 * Make sure that we have a record for this connection.
	 */
	oncc = avl_find(&ncp->nc_conns, ncc, &avlwhere);
	if (oncc == NULL) {
		(void) strlcpy(ncc->ncc_state, state, sizeof (ncc->ncc_state));
		avl_insert(&ncp->nc_conns, ncc, avlwhere);
	} else {
		free(ncc);
		ncc = oncc;
	}

	/*
	 * Update the record to refer to this source.  We only actually keep two
	 * sources.
	 */
	if (ncc->ncc_nsources < 2) {
		ncc->ncc_sources[ncc->ncc_nsources++] = ncs;
	} else if (ncc->ncc_nsources < UINT8_MAX) {
		ncc->ncc_nsources++;
	}

	return (0);
}

/*
 * Parse the netstat-reported IP address and TCP port into "outbuf" (for the IP
 * address) and *portp (for the port).  Returns 0 on success.  On failure,
 * returns -1 with undefined contents of the input arguments.
 */
static int
nc_parse_ipport(char *outbuf, size_t outbufsz, uint16_t *portp, char *str)
{
	char *dot;
	char *endp;
	long portval;

	dot = strrchr(str, '.');
	if (dot == NULL) {
		warnx("bad IP/port pair");
		return (-1);
	}

	*dot = '\0';
	(void) strlcpy(outbuf, str, outbufsz);

	errno = 0;
	portval = strtol(dot + 1, &endp, 10);
	if (errno != 0 || portval < 0 ||
	    portval > UINT16_MAX || *endp != '\0') {
		warnx("bad TCP port");
		return (-1);
	}

	*portp = (uint16_t)portval;
	return (0);
}

/*
 * avl tree comparator for connections.
 */
static int
nc_conn_compare(const void *vncc1, const void *vncc2)
{
	const ncconn_t *ncc1 = vncc1;
	const ncconn_t *ncc2 = vncc2;
	int cmp;

	cmp = strcmp(ncc1->ncc_ip1, ncc2->ncc_ip1);
	if (cmp == 0)
		cmp = ncc1->ncc_port1 - ncc2->ncc_port1;
	if (cmp == 0)
		cmp = strcmp(ncc1->ncc_ip2, ncc2->ncc_ip2);
	if (cmp == 0)
		cmp = ncc1->ncc_port2 - ncc2->ncc_port2;

	return (cmp < 0 ? -1 : (cmp == 0 ? 0 : 1));
}

/*
 * avl tree comparator for sources.
 */
static int
nc_source_compare(const void *vncs1, const void *vncs2)
{
	const ncsource_t *ncs1 = vncs1;
	const ncsource_t *ncs2 = vncs2;
	int cmp;

	cmp = strcmp(ncs1->ncs_ip, ncs2->ncs_ip);
	return (cmp < 0 ? -1 : (cmp == 0 ? 0 : 1));
}
