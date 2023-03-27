#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <json-c/json.h>

#include "respondd-common.h"

void respondd_common_board_close(struct respondd_board *board)
{
	if (board->json) {
		json_object_put(board->json);
	}

	if (board->json) {
		munmap(board->json, board->st.st_size);
	}

	if (board->fd >= 0) {
		close(board->fd);
	}
}

struct respondd_board *respondd_common_board_open()
{
	int fd;
	int ret;
	struct respondd_board *board;

	board = malloc(sizeof(struct respondd_board));
	if (!board)
		return NULL;

	memset(board, 0, sizeof(struct respondd_board));

	fd = open("/etc/board.json", O_RDONLY);
	if (fd < 0) {
		return NULL;
	}
	board->fd = fd;

	ret = fstat(fd, &board->st);
	if (ret < 0) {
		respondd_common_board_close(board);
		return NULL;
	}

	board->content = mmap(NULL, board->st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (!board->content) {
		respondd_common_board_close(board);
		return NULL;
	}

	board->json = json_tokener_parse(board->content);
	if (!board->json) {
		respondd_common_board_close(board);
		return NULL;
	}

	return board;
}

int respondd_common_mac_to_node_id(char *mac, char *node_id) {
	int i, j;

	j = 0;
	memset(node_id, 0, NODE_ID_LEN + 1);
	for (i = 0; i < MAC_ADDRESS_LEN; i++) {
		if (mac[i] == ':')
			continue;
		
		node_id[j] = mac[i];
		j++;
	}

	return 0;
}

int respondd_common_read_primary_mac(char *buf) {
	FILE *fp;
	int sz, ret;
	ret = 0;

	fp = popen("sh /usr/lib/gluon-respondd/label-mac.sh", "r");
	if (!fp)
		return 1;
	
	if (!fgets(buf, MAC_ADDRESS_LEN+1, fp)) {
		ret = 1;
		goto out;
	}

	/* ToDo: Check if buffer contains valid MAC*/
out:
	pclose(fp);
	return ret;
}