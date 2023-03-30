/* SPDX-FileCopyrightText: 2016-2019, Matthias Schiffer <mschiffer@universe-factory.net> */
/* SPDX-License-Identifier: BSD-2-Clause */

#include "respondd-common.h"

#include <json-c/json.h>
#include <uci.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <net/if.h>
#include <netinet/in.h>

#include <linux/if_addr.h>
#include <linux/rtnetlink.h>

#define RELEASE_KEY "OPENWRT_RELEASE=\""

struct respondd_nodeinfo_data {
	struct json_object *node_id;
	struct json_object *primary_mac;
};

struct ip_address_information {
	unsigned int ifindex;
	struct json_object *addresses;
};

static int get_addresses_cb(struct nl_msg *msg, void *arg) {
	struct ip_address_information *info = (struct ip_address_information*) arg;

	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct ifaddrmsg *msg_content = NLMSG_DATA(nlh);
	int remaining = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	struct rtattr *hdr;

	for (hdr = IFA_RTA(msg_content); RTA_OK(hdr, remaining); hdr = RTA_NEXT(hdr, remaining)) {
		char addr_str_buf[INET6_ADDRSTRLEN];

		/* We are only interested in IP-addresses of br-client */
		if (hdr->rta_type != IFA_ADDRESS ||
			msg_content->ifa_index != info->ifindex ||
			msg_content->ifa_flags & (IFA_F_TENTATIVE|IFA_F_DEPRECATED)) {
			continue;
		}

		if (inet_ntop(AF_INET6, (struct in6_addr *) RTA_DATA(hdr), addr_str_buf, INET6_ADDRSTRLEN)) {
			json_object_array_add(info->addresses, json_object_new_string(addr_str_buf));
		}
	}

	return NL_OK;
}

static void get_addresses_iface(const char *iface, struct json_object *output) {
	struct ip_address_information info = {
		.ifindex = if_nametoindex(iface),
		.addresses = output,
	};
	int err;

	if (!info.ifindex)
		return;

	/* Open socket */
	struct nl_sock *socket = nl_socket_alloc();
	if (!socket) {
		return;
	}

	err = nl_connect(socket, NETLINK_ROUTE);
	if (err < 0) {
		goto out_free;
	}

	/* Send message */
	struct ifaddrmsg rt_hdr = { .ifa_family = AF_INET6, };
	err = nl_send_simple(socket, RTM_GETADDR, NLM_F_REQUEST | NLM_F_ROOT, &rt_hdr, sizeof(struct ifaddrmsg));
	if (err < 0) {
		goto out_free;
	}

	/* Retrieve answer. Message is handled by get_addresses_cb */
	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, get_addresses_cb, &info);
	nl_recvmsgs_default(socket);

out_free:
	nl_socket_free(socket);
	return;
}

static struct uci_section * get_first_section(struct uci_package *p, const char *type) {
	struct uci_element *e;
	uci_foreach_element(&p->sections, e) {
		struct uci_section *s = uci_to_section(e);
		if (!strcmp(s->type, type))
			return s;
	}

	return NULL;
}

static struct json_object *get_addresses() {
	struct json_object *jso = json_object_new_array();
	struct uci_context *ctx = uci_alloc_context();

	if (!ctx)
		return jso;
	ctx->flags &= ~UCI_FLAG_STRICT;

	struct uci_package *p;
	if (!uci_load(ctx, "respondd-gluon", &p)) {
		struct uci_section *s = get_first_section(p, "ip-addresses");
		if (!s)
			goto out;
		
		struct uci_option *o = uci_lookup_option(ctx, s, "interface");
		/* Handle both list as well as strings */
		if (o->type == UCI_TYPE_STRING) {
			/* String */
			get_addresses_iface(o->v.string, jso);
		} else {
			/* List */
			struct uci_element *l;
			uci_foreach_element(&o->v.list, l) {
				if (!l->name)
					continue;
				
				get_addresses_iface(l->name, jso);
			}
		}
	}
out:
	if (ctx)
		uci_free_context(ctx);

	return jso;
}

static struct json_object *get_double(struct uci_context *ctx, struct uci_section *s, const char *name)
{
	const char *val = uci_lookup_option_string(ctx, s, name);
	if (!val || !*val)
		return NULL;
	
	char *end;
	double d = strtod(val, &end);
	if (*end)
		return NULL;
	
	struct json_object *jso = json_object_new_double(d);
	json_object_set_serializer(jso, json_object_double_to_json_string, "%.8f", NULL);
	return jso;
}

static struct json_object *get_location()
{
	struct json_object *obj = json_object_new_object();
	if (!obj)
		return NULL;
	
	struct uci_context *ctx = uci_alloc_context();
	if (!ctx)
		return obj;
	ctx->flags &= ~UCI_FLAG_STRICT;

	struct uci_package *p;
	if (!uci_load(ctx, "respondd-gluon", &p)) {
		struct uci_section *s = get_first_section(p, "location");
		if (!s)
			goto out;
		
		struct json_object *latitude = get_double(ctx, s, "latitude");
		if (latitude)
			json_object_object_add(obj, "latitude", latitude);
		struct json_object *longitude = get_double(ctx, s, "longitude");
		if (longitude)
			json_object_object_add(obj, "longitude", longitude);	
	}
out:
	if (ctx)
		uci_free_context(ctx);

	return obj;
}

static const char *get_release() {
	static char release[50] = {};
	char *line = NULL;
	size_t line_size = 0;
	size_t read;
	char *p;
	FILE *fp;

	fp = fopen("/etc/os-release", "r");
	if (!fp)
		return NULL;
	
	while ((read = getline(&line, &line_size, fp)) != -1) {
		/* Check if line is what we are after */
		if (strstr(line, RELEASE_KEY) != line)
			continue;
		
		p = line + strlen(RELEASE_KEY);
		if (strlen(p) < 3)
			continue;

		memcpy(release, p, strlen(p) * sizeof(char));
		release[strlen(p) - 2] = 0;
	}

	if (line)
		free(line);

	fclose(fp);
	if (release[0] != 0)
		return release;

	return NULL;
}

static struct json_object * get_hostname(void) {
	struct json_object *ret = NULL;

	struct uci_context *ctx = uci_alloc_context();
	if (!ctx)
		return NULL;
	ctx->flags &= ~UCI_FLAG_STRICT;

	char section[] = "system.@system[0]";
	struct uci_ptr ptr;
	if (uci_lookup_ptr(ctx, &ptr, section, true))
		goto error;

	struct uci_section *s = ptr.s;

	const char *hostname = uci_lookup_option_string(ctx, s, "pretty_hostname");

	if (!hostname)
		hostname = uci_lookup_option_string(ctx, s, "hostname");

	ret = json_object_new_string(hostname);

error:
	uci_free_context(ctx);

	return ret;
}

const char *get_model()
{
	struct respondd_board *board;
	static char model_name[50] = {};
	struct json_object *model, *name;
	const char *board_model_name;

	board = respondd_common_board_open();
	if (!board)
		return NULL;
	
	model = json_object_object_get(board->json, "model");
	if (!model)
		goto out;
	
	name = json_object_object_get(model, "name");
	if (!model)
		goto out;
	
	board_model_name = json_object_get_string(name);
	strncpy(model_name, board_model_name, 50);
	
out:
	respondd_common_board_close(board);
	if (model_name[0] != 0)
		return model_name;
	
	return NULL;
}

struct json_object * respondd_provider_nodeinfo(void) {
	struct json_object *ret = json_object_new_object();
	char node_id[NODE_ID_LEN + 1] = {};
	char primary_mac[MAC_ADDRESS_LEN + 1] = {};

	if (respondd_common_read_primary_mac(primary_mac))
		return NULL;
	
	respondd_common_mac_to_node_id(primary_mac, node_id);

	json_object_object_add(ret, "node_id", json_object_new_string(node_id));
	json_object_object_add(ret, "hostname", get_hostname());

	struct json_object *hardware = json_object_new_object();

	const char *model = get_model();
	if (model)
		json_object_object_add(hardware, "model", json_object_new_string(model));

	json_object_object_add(hardware, "nproc", json_object_new_int(sysconf(_SC_NPROCESSORS_ONLN)));
	json_object_object_add(ret, "hardware", hardware);

	struct json_object *network = json_object_new_object();
	json_object_object_add(network, "mac", json_object_new_string(primary_mac));
	json_object_object_add(network, "addresses", get_addresses());
	json_object_object_add(ret, "network", network);

	struct json_object *software = json_object_new_object();
	struct json_object *software_firmware = json_object_new_object();
	const char *base = get_release();
	if (base)
		json_object_object_add(software_firmware, "base", json_object_new_string(base));
	json_object_object_add(software, "firmware", software_firmware);
	json_object_object_add(ret, "software", software);

	struct json_object *system = json_object_new_object();
	json_object_object_add(system, "site_code", json_object_new_string("ffda"));
	json_object_object_add(ret, "system", system);

	struct json_object *location = get_location();
	if (location)
		json_object_object_add(ret, "location", location);

	return ret;
}
