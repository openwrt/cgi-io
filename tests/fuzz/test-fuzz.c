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

#include "util.h"

static void fuzz_parse_command(const char *buf)
{
	char **p = parse_command(buf);
	if (p)
		free(p);
}

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t size)
{
	char *p = NULL;
	char *fields[] = { "sessionid", NULL, "path", NULL, "filename", NULL, "mimetype", NULL };
	char *buf = calloc(1, size+1);
	memcpy(buf, input, size);

	urldecode(buf);
	fuzz_parse_command(buf);
	p = canonicalize_path(buf, size+1);
	if (p)
		free(p);

	p = postdecode_fields(buf, size+1, fields, 4);
	if (!p)
		return 0;

	free(buf);

	return 0;
}
