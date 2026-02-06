// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025 AMD. All rights reserved. */
#include <util/parse-options.h>
#include <cxl/libcxl.h>
#include <cxl/filter.h>
#include <util/log.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

static bool debug;

static struct proto_inject_params {
	const char *proto;
	const char *severity;
} proto_inj_param;

static const struct option proto_inject_options[] = {
	OPT_STRING('p', "protocol", &proto_inj_param.proto, "mem/cache",
		   "Which CXL protocol error to inject into <dport>"),
	OPT_STRING('s', "severity", &proto_inj_param.severity,
		   "correctable/uncorrectable/fatal",
		   "Severity of CXL protocol to inject into <dport>"),
#ifdef ENABLE_DEBUG
	OPT_BOOLEAN(0, "debug", &debug, "turn on debug output"),
#endif
	OPT_END(),
};

static struct log_ctx iel;

static struct cxl_protocol_error *find_cxl_proto_err(struct cxl_ctx *ctx,
						     const char *type,
						     const char *severity)
{
	struct cxl_protocol_error *pe;
	char perror[256] = { 0 };
	size_t len;

	len = snprintf(perror, sizeof(perror), "%s-%s", type,
		       severity);
	if (len >= sizeof(perror)) {
		log_err(&iel, "Buffer too small\n");
		return NULL;
	}

	cxl_protocol_error_foreach(ctx, pe) {
		if (strcmp(perror, cxl_protocol_error_get_str(pe)) == 0)
			return pe;
	}

	log_err(&iel, "Invalid CXL protocol error type: %s\n", perror);
	return NULL;
}

static struct cxl_dport *find_cxl_dport(struct cxl_ctx *ctx, const char *devname)
{
	struct cxl_dport *dport;
	struct cxl_port *port;
	struct cxl_bus *bus;

	cxl_bus_foreach(ctx, bus)
		cxl_port_foreach_all(cxl_bus_get_port(bus), port)
			cxl_dport_foreach(port, dport)
				if (util_cxl_dport_filter(dport, devname))
					return dport;

	log_err(&iel, "Downstream port \"%s\" not found\n", devname);
	return NULL;
}

static int inject_proto_err(struct cxl_ctx *ctx, const char *devname,
			    struct cxl_protocol_error *perror)
{
	struct cxl_dport *dport;
	int rc;

	if (!devname) {
		log_err(&iel, "No downstream port specified for injection\n");
		return -EINVAL;
	}

	dport = find_cxl_dport(ctx, devname);
	if (!dport)
		return -ENODEV;

	rc = cxl_dport_protocol_error_inject(dport,
					     cxl_protocol_error_get_num(perror));
	if (rc)
		return rc;

	log_info(&iel, "injected %s protocol error.\n",
		 cxl_protocol_error_get_str(perror));
	return 0;
}

static int inject_protocol_action(int argc, const char **argv,
				  struct cxl_ctx *ctx,
				  const struct option *options,
				  const char *usage)
{
	struct cxl_protocol_error *perr;
	const char * const u[] = {
		usage,
		NULL
	};
	int rc = -EINVAL;

	log_init(&iel, "cxl inject-protocol-error", "CXL_INJECT_LOG");
	argc = parse_options(argc, argv, options, u, 0);

	if (debug) {
		cxl_set_log_priority(ctx, LOG_DEBUG);
		iel.log_priority = LOG_DEBUG;
	} else {
		iel.log_priority = LOG_INFO;
	}

	if (argc != 1 || proto_inj_param.proto == NULL ||
	    proto_inj_param.severity == NULL) {
		usage_with_options(u, options);
		return rc;
	}

	perr = find_cxl_proto_err(ctx, proto_inj_param.proto,
				  proto_inj_param.severity);
	if (perr) {
		rc = inject_proto_err(ctx, argv[0], perr);
		if (rc)
			log_err(&iel, "Failed to inject error: %d\n", rc);
	}

	return rc;
}

int cmd_inject_protocol_error(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = inject_protocol_action(argc, argv, ctx, proto_inject_options,
					"inject-protocol-error <dport> -p <protocol> -s <severity> [<options>]");

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
