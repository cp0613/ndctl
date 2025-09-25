// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2015-2025 Intel Corporation. All rights reserved.
#include <errno.h>
#include <util/bitmap.h>
#include <util/json.h>
#include <cxl/libcxl.h>

#include "../util/event_trace.h"

/* CXL Spec 3.1 Table 8-140 Media Error Record */
#define CXL_POISON_SOURCE_MAX 7
static const char *const poison_source[] = { "Unknown", "External", "Internal",
					     "Injected", "Reserved", "Reserved",
					     "Reserved", "Vendor Specific" };

/* CXL Spec 3.1 Table 8-139 Get Poison List Output Payload */
#define CXL_POISON_FLAG_MORE BIT(0)
#define CXL_POISON_FLAG_OVERFLOW BIT(1)
#define CXL_POISON_FLAG_SCANNING BIT(2)

static int poison_event_to_json(struct tep_event *event,
				struct tep_record *record,
				struct event_ctx *e_ctx)
{
	struct cxl_poison_ctx *p_ctx = e_ctx->poison_ctx;
	struct json_object *jp, *jobj, *jpoison = p_ctx->jpoison;
	struct cxl_memdev *memdev = p_ctx->memdev;
	struct cxl_region *region = p_ctx->region;
	unsigned long flags = e_ctx->json_flags;
	const char *region_name = NULL;
	char flag_str[32] = { '\0' };
	bool overflow = false;
	u8 source, pflags;
	u64 offset, ts;
	u32 length;
	char *str;
	int len;

	jp = json_object_new_object();
	if (!jp)
		return -ENOMEM;

	/* Skip records not in this region when listing by region */
	if (region)
		region_name = cxl_region_get_devname(region);
	if (region_name)
		str = tep_get_field_raw(NULL, event, "region", record, &len, 0);
	if ((region_name) && (strcmp(region_name, str) != 0)) {
		json_object_put(jp);
		return 0;
	}
	/* Include offset,length by region (hpa) or by memdev (dpa) */
	if (region) {
		offset = trace_get_field_u64(event, record, "hpa");
		if (offset != ULLONG_MAX) {
			offset = offset - cxl_region_get_resource(region);
			jobj = util_json_object_hex(offset, flags);
			if (jobj)
				json_object_object_add(jp, "offset", jobj);
		}
	} else if (memdev) {
		offset = trace_get_field_u64(event, record, "dpa");
		if (offset != ULLONG_MAX) {
			jobj = util_json_object_hex(offset, flags);
			if (jobj)
				json_object_object_add(jp, "offset", jobj);
		}
	}
	length = trace_get_field_u32(event, record, "dpa_length");
	jobj = util_json_object_size(length, flags);
	if (jobj)
		json_object_object_add(jp, "length", jobj);

	/* Always include the poison source */
	source = trace_get_field_u8(event, record, "source");
	if (source <= CXL_POISON_SOURCE_MAX)
		jobj = json_object_new_string(poison_source[source]);
	else
		jobj = json_object_new_string("Reserved");
	if (jobj)
		json_object_object_add(jp, "source", jobj);

	/* Include flags and overflow time if present */
	pflags = trace_get_field_u8(event, record, "flags");
	if (pflags && pflags < UCHAR_MAX) {
		if (pflags & CXL_POISON_FLAG_MORE)
			strcat(flag_str, "More,");
		if (pflags & CXL_POISON_FLAG_SCANNING)
			strcat(flag_str, "Scanning,");
		if (pflags & CXL_POISON_FLAG_OVERFLOW) {
			strcat(flag_str, "Overflow,");
			overflow = true;
		}
		jobj = json_object_new_string(flag_str);
		if (jobj)
			json_object_object_add(jp, "flags", jobj);
	}
	if (overflow) {
		ts = trace_get_field_u64(event, record, "overflow_ts");
		jobj = util_json_object_hex(ts, flags);
		if (jobj)
			json_object_object_add(jp, "overflow_t", jobj);
	}
	json_object_array_add(jpoison, jp);

	return 0;
}

static struct json_object *
util_cxl_poison_events_to_json(struct tracefs_instance *inst,
			       struct cxl_poison_ctx *p_ctx,
			       unsigned long flags)
{
	struct event_ctx ectx = {
		.event_name = "cxl_poison",
		.event_pid = getpid(),
		.system = "cxl",
		.poison_ctx = p_ctx,
		.json_flags = flags,
		.parse_event = poison_event_to_json,
	};
	int rc;

	p_ctx->jpoison = json_object_new_array();
	if (!p_ctx->jpoison)
		return NULL;

	rc = trace_event_parse(inst, &ectx);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse events: %d\n", rc);
		goto put_jobj;
	}
	if (json_object_array_length(p_ctx->jpoison) == 0)
		goto put_jobj;

	return p_ctx->jpoison;

put_jobj:
	json_object_put(p_ctx->jpoison);
	return NULL;
}

struct json_object *util_cxl_poison_list_to_json(struct cxl_region *region,
			struct cxl_memdev *memdev, unsigned long flags)
{
	struct json_object *jpoison = NULL;
	struct cxl_poison_ctx p_ctx;
	struct tracefs_instance *inst;
	int rc;

	inst = tracefs_instance_create("cxl list");
	if (!inst) {
		fprintf(stderr, "tracefs_instance_create() failed\n");
		return NULL;
	}

	rc = trace_event_enable(inst, "cxl", "cxl_poison");
	if (rc < 0) {
		fprintf(stderr, "Failed to enable trace: %d\n", rc);
		goto err_free;
	}

	if (region)
		rc = cxl_region_trigger_poison_list(region);
	else
		rc = cxl_memdev_trigger_poison_list(memdev);
	if (rc)
		goto err_free;

	rc = trace_event_disable(inst);
	if (rc < 0) {
		fprintf(stderr, "Failed to disable trace: %d\n", rc);
		goto err_free;
	}

	p_ctx = (struct cxl_poison_ctx){
		.region = region,
		.memdev = memdev,
	};
	jpoison = util_cxl_poison_events_to_json(inst, &p_ctx, flags);

err_free:
	tracefs_instance_free(inst);
	return jpoison;
}
