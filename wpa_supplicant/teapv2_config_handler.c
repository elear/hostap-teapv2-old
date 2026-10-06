/*
 * External TEAPv2 client-configuration event handler
 *
 * This software may be distributed under the terms of the BSD license.
 */

#include "includes.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "common.h"
#include "common/wpa_ctrl.h"
#include "utils/json.h"
#include "network_fields.h"

#define SSID_MEMBER \
	"example-teapv2-dhcpv6-vendor-options:vendor-cisco-80211-ssid"
#define PROXY_MEMBER \
	"example-teapv2-dhcpv6-vendor-options:vendor-cisco-tls-proxy"

static struct wpa_ctrl *command_conn;
static struct wpa_ctrl *monitor_conn;
static const char *tls_proxy_file;
static u32 last_generation;

struct clone_record {
	struct clone_record *next;
	int source_id;
	char ssid[33];
};

static struct clone_record *clone_records;


static int ctrl_command(const char *cmd, char *reply, size_t reply_size)
{
	size_t len = reply_size - 1;

	if (wpa_ctrl_request(command_conn, cmd, os_strlen(cmd), reply, &len,
			     NULL) < 0)
		return -2;
	reply[len] = '\0';
	while (len && (reply[len - 1] == '\n' || reply[len - 1] == '\r'))
		reply[--len] = '\0';
	return os_strncmp(reply, "FAIL", 4) == 0 ? -1 : (int) len;
}


static int clone_network(int source_id, const char *ssid)
{
	char cmd[256], reply[8192];
	int dest_id, i;
	int res;
	size_t ssid_len = os_strlen(ssid);
	char ssid_hex[65];
	struct clone_record *record;

	if (!ssid_len || ssid_len > 32)
		return -1;
	for (record = clone_records; record; record = record->next) {
		if (record->source_id == source_id &&
		    os_strcmp(record->ssid, ssid) == 0)
			return 0;
	}
	os_snprintf(cmd, sizeof(cmd), "GET_NETWORK %d ssid", source_id);
	if (ctrl_command(cmd, reply, sizeof(reply)) < 0)
		return -1;
	wpa_snprintf_hex(ssid_hex, sizeof(ssid_hex), (const u8 *) ssid,
			 ssid_len);
	if (os_strcmp(reply, ssid_hex) == 0 ||
	    (reply[0] == '"' && os_strlen(reply) == ssid_len + 2 &&
	     os_memcmp(reply + 1, ssid, ssid_len) == 0 &&
	     reply[ssid_len + 1] == '"'))
		return 0;
	if (ctrl_command("ADD_NETWORK", reply, sizeof(reply)) < 0)
		return -1;
	dest_id = atoi(reply);

	for (i = 0; i < (int) ARRAY_SIZE(wpas_network_fields); i++) {
		const char *field = wpas_network_fields[i];

		if (os_strcmp(field, "ssid") == 0 ||
		    os_strcmp(field, "disabled") == 0)
			continue;
		os_snprintf(cmd, sizeof(cmd), "GET_NETWORK %d %s",
			    source_id, field);
		res = ctrl_command(cmd, reply, sizeof(reply));
		if (res == -1)
			continue;
		if (res < 0)
			goto fail;
		os_snprintf(cmd, sizeof(cmd), "DUP_NETWORK %d %d %s",
			    source_id, dest_id, field);
		if (ctrl_command(cmd, reply, sizeof(reply)) < 0)
			goto fail;
	}

	os_snprintf(cmd, sizeof(cmd), "SET_NETWORK %d ssid %s", dest_id,
		    ssid_hex);
	if (ctrl_command(cmd, reply, sizeof(reply)) < 0)
		goto fail;

	os_snprintf(cmd, sizeof(cmd), "GET_NETWORK %d disabled", source_id);
	res = ctrl_command(cmd, reply, sizeof(reply));
	if (res >= 0) {
		os_snprintf(cmd, sizeof(cmd), "DUP_NETWORK %d %d disabled",
			    source_id, dest_id);
		if (ctrl_command(cmd, reply, sizeof(reply)) < 0)
			goto fail;
	} else if (res == -2)
		goto fail;
	wpa_printf(MSG_INFO,
		   "TEAPv2 configuration: created cloned network id=%d from id=%d",
		   dest_id, source_id);
	record = os_zalloc(sizeof(*record));
	if (record) {
		record->source_id = source_id;
		os_strlcpy(record->ssid, ssid, sizeof(record->ssid));
		record->next = clone_records;
		clone_records = record;
	}
	return 0;

fail:
	os_snprintf(cmd, sizeof(cmd), "REMOVE_NETWORK %d", dest_id);
	ctrl_command(cmd, reply, sizeof(reply));
	return -1;
}


static int valid_proxy_url(const char *url)
{
	const char *authority, *end;
	size_t len = os_strlen(url);

	if (!len || len > 2048 || os_strchr(url, '#'))
		return 0;
	if (os_strncmp(url, "http://", 7) == 0)
		authority = url + 7;
	else if (os_strncmp(url, "https://", 8) == 0)
		authority = url + 8;
	else
		return 0;
	end = os_strchr(authority, '/');
	if (!end)
		end = authority + os_strlen(authority);
	return end > authority && !memchr(authority, '@', end - authority);
}


static int sync_proxy_file(const char *url)
{
	char *tmp, *slash;
	int fd, ret = -1;
	size_t len;

	if (!tls_proxy_file)
		return 0;
	if (!url) {
		if (unlink(tls_proxy_file) < 0 && errno != ENOENT)
			return -1;
		return 0;
	}
	if (!valid_proxy_url(url))
		return -1;
	tmp = os_malloc(os_strlen(tls_proxy_file) + 32);
	if (!tmp)
		return -1;
	os_snprintf(tmp, os_strlen(tls_proxy_file) + 32, "%s.tmp.%ld",
		    tls_proxy_file, (long) getpid());
	slash = os_strrchr(tmp, '/');
	if (!slash) {
		os_free(tmp);
		return -1;
	}
	fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0)
		goto out;
	len = os_strlen(url);
	if (write(fd, url, len) == (ssize_t) len && write(fd, "\n", 1) == 1 &&
	    fsync(fd) == 0 && close(fd) == 0) {
		fd = -1;
		if (rename(tmp, tls_proxy_file) == 0)
			ret = 0;
	}
	if (fd >= 0)
		close(fd);
	if (ret)
		unlink(tmp);
out:
	os_free(tmp);
	return ret;
}


static int apply_json(const char *text, size_t len, int source_id,
		      int apply_ssid)
{
	struct json_token *root, *set, *value;
	const char *proxy = NULL;
	int proxy_conflict = 0, proxy_invalid = 0, failed = 0;

	root = json_parse(text, len);
	if (!root || root->type != JSON_ARRAY)
		goto fail;
	for (set = root->child; set; set = set->sibling) {
		if (set->type != JSON_OBJECT)
			goto fail;
		value = json_get_member(set, SSID_MEMBER);
		if (apply_ssid && value) {
			if (value->type != JSON_STRING || !value->string ||
			    clone_network(source_id, value->string) < 0)
				failed = 1;
		}
		value = json_get_member(set, PROXY_MEMBER);
		if (value) {
			if (value->type != JSON_STRING || !value->string ||
			    !valid_proxy_url(value->string)) {
				proxy_invalid = 1;
				continue;
			}
			if (proxy && os_strcmp(proxy, value->string) != 0)
				proxy_conflict = 1;
			else
				proxy = value->string;
		}
	}
	if (proxy_conflict || proxy_invalid) {
		wpa_printf(MSG_ERROR,
			   "TEAPv2 configuration: invalid or conflicting TLS proxy options");
		failed = 1;
	} else if (sync_proxy_file(proxy) < 0) {
		wpa_printf(MSG_ERROR,
			   "TEAPv2 configuration: could not update TLS proxy file");
		failed = 1;
	}
	json_free(root);
	return failed ? -1 : 0;
fail:
	json_free(root);
	return -1;
}


static int fetch_and_apply(u32 generation, int network_id, int apply_ssid)
{
	char cmd[64], reply[8192];
	int len;

	if (generation)
		os_snprintf(cmd, sizeof(cmd), "TEAPV2_CLIENT_CONFIG %u",
			    generation);
	else
		os_strlcpy(cmd, "TEAPV2_CLIENT_CONFIG", sizeof(cmd));
	len = ctrl_command(cmd, reply, sizeof(reply));
	if (len < 0) {
		if (!generation && os_strcmp(reply, "FAIL-NO-RESULT") == 0)
			return sync_proxy_file(NULL);
		return -1;
	}
	return apply_json(reply, len, network_id, apply_ssid);
}


static void process_event(char *event)
{
	char *pos, *gen_pos, *net_pos;
	u32 generation;
	int network_id;

	pos = os_strchr(event, '>');
	if (pos)
		event = pos + 1;
	if (os_strncmp(event, WPA_EVENT_TEAPV2_CLIENT_CONFIG,
		       os_strlen(WPA_EVENT_TEAPV2_CLIENT_CONFIG)) != 0)
		return;
	gen_pos = os_strstr(event, "generation=");
	net_pos = os_strstr(event, "network_id=");
	if (!gen_pos || !net_pos)
		return;
	generation = strtoul(gen_pos + 11, NULL, 10);
	network_id = atoi(net_pos + 11);
	if (!generation || generation == last_generation || network_id < 0)
		return;
	if (fetch_and_apply(generation, network_id, 1) == 0)
		last_generation = generation;
	else
		wpa_printf(MSG_ERROR,
			   "TEAPv2 configuration: generation %u was not fully applied",
			   generation);
}


static int read_config(const char *path)
{
	FILE *f;
	char line[4096], *pos;

	f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		pos = os_strchr(line, '\n');
		if (pos)
			*pos = '\0';
		if (os_strncmp(line, "tls_proxy_file=", 15) == 0) {
			os_free((void *) tls_proxy_file);
			tls_proxy_file = os_strdup(line + 15);
		}
	}
	fclose(f);
	return 0;
}


int main(int argc, char *argv[])
{
	const char *ifname = NULL, *ctrl_dir = "/var/run/wpa_supplicant";
	char path[512], event[8192];
	int c, fd;

	for (c = 1; c < argc; c++) {
		if (os_strcmp(argv[c], "-i") == 0 && c + 1 < argc)
			ifname = argv[++c];
		else if (os_strcmp(argv[c], "-p") == 0 && c + 1 < argc)
			ctrl_dir = argv[++c];
		else if (os_strcmp(argv[c], "-c") == 0 && c + 1 < argc) {
			if (read_config(argv[++c]) < 0)
				return 1;
		} else {
			fprintf(stderr,
				"usage: %s -i ifname [-p ctrl-dir] [-c config]\n",
				argv[0]);
			return 1;
		}
	}
	if (!ifname)
		return 1;
	os_snprintf(path, sizeof(path), "%s/%s", ctrl_dir, ifname);
	command_conn = wpa_ctrl_open(path);
	monitor_conn = wpa_ctrl_open(path);
	if (!command_conn || !monitor_conn || wpa_ctrl_attach(monitor_conn) < 0)
		return 1;

	/* Existing state can safely initialize the proxy output at startup. */
	fetch_and_apply(0, -1, 0);
	fd = wpa_ctrl_get_fd(monitor_conn);
	for (;;) {
		fd_set rfds;
		size_t len = sizeof(event) - 1;

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		if (select(fd + 1, &rfds, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (wpa_ctrl_recv(monitor_conn, event, &len) < 0)
			break;
		event[len] = '\0';
		process_event(event);
	}
	wpa_ctrl_detach(monitor_conn);
	wpa_ctrl_close(monitor_conn);
	wpa_ctrl_close(command_conn);
	while (clone_records) {
		struct clone_record *next = clone_records->next;
		os_free(clone_records);
		clone_records = next;
	}
	os_free((void *) tls_proxy_file);
	return 1;
}
