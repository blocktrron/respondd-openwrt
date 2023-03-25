#include <stdio.h>
#include <stdlib.h>

#include "respondd-common.h"

#define NODE_ID_PATH    "/lib/respondd/nodeid"

int respondd_common_read_node_id(char *buf) {
	FILE *f;
	char c;
	int i, ret = 1;

	f = fopen(NODE_ID_PATH, "r");
	if (!f)
		goto out;
	
	for (i = 0; i < NODE_ID_LEN; i++) {
		c = fgetc(f);
		if (c == EOF)
			goto out;
		buf[i] = c;
	}

	if (i == NODE_ID_LEN)
		ret = 0;

out:
	if (f)
		fclose(f);
	return ret;
}