#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "multipart_parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t size)
{
	char *buf = NULL;
	multipart_parser *p;
	static multipart_parser_settings s = {
		.on_part_data        = NULL,
		.on_headers_complete = NULL,
		.on_part_data_end    = NULL,
		.on_header_field     = NULL,
		.on_header_value     = NULL,
	};
	buf = calloc(1, size + 1);
	if (!buf)
		return 0;

	memcpy(buf, input, size);
	p = multipart_parser_init(buf, &s);
	if (!p) {
		free(buf);
		return 0;
	}

	multipart_parser_execute(p, buf, size + 1);
	multipart_parser_free(p);
	free(buf);

	return 0;
}
