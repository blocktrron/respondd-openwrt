#pragma once

#include <json-c/json.h>
#include <sys/stat.h>

#define NODE_ID_LEN 12
#define MAC_ADDRESS_LEN 17

struct respondd_board {
	int fd;
	char *content;
	struct stat st;
	struct json_object *json;
};

int respondd_common_mac_to_node_id(char *mac, char *node_id);

int respondd_common_read_primary_mac(char *buf);

void respondd_common_board_close(struct respondd_board *board);

struct respondd_board *respondd_common_board_open();
