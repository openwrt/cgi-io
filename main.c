/*
 * cgi-io - LuCI non-RPC helper
 *
 *   Copyright (C) 2013 Jo-Philipp Wich <jo@mein.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _GNU_SOURCE /* splice(), SPLICE_F_MORE */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/sendfile.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include <libubus.h>
#include <libubox/blobmsg.h>

#include "util.h"
#include "multipart_parser.h"

#ifndef O_TMPFILE
#define O_TMPFILE	(020000000 | O_DIRECTORY)
#endif

#define READ_BLOCK 4096

enum part {
	PART_UNKNOWN,
	PART_SESSIONID,
	PART_FILENAME,
	PART_FILEMODE,
	PART_FILEDATA
};

const char *parts[] = {
	"(bug)",
	"sessionid",
	"filename",
	"filemode",
	"filedata",
};

struct state
{
	bool is_content_disposition;
	enum part parttype;
	char *sessionid;
	char *filename;
	bool filedata;
	int filemode;
	int filefd;
	int tempfd;
};

static struct state st;

#ifndef UNIT_TESTING

enum {
	SES_ACCESS,
	__SES_MAX,
};

static const struct blobmsg_policy ses_policy[__SES_MAX] = {
	[SES_ACCESS] = { .name = "access", .type = BLOBMSG_TYPE_BOOL },
};

static void
session_access_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *tb[__SES_MAX];
	bool *allow = (bool *)req->priv;

	if (!msg)
		return;

	blobmsg_parse(ses_policy, __SES_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[SES_ACCESS])
		*allow = blobmsg_get_bool(tb[SES_ACCESS]);
}
#endif

static bool
session_access(const char *sid, const char *scope, const char *obj, const char *func)
{
#ifdef UNIT_TESTING
	return true;
#else
	uint32_t id;
	bool allow = false;
	struct ubus_context *ctx;
	static struct blob_buf req;

	ctx = ubus_connect(NULL);

	if (!ctx || !obj || ubus_lookup_id(ctx, "session", &id))
		goto out;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "ubus_rpc_session", sid);
	blobmsg_add_string(&req, "scope", scope);
	blobmsg_add_string(&req, "object", obj);
	blobmsg_add_string(&req, "function", func);

	ubus_invoke(ctx, id, "access", req.head, session_access_cb, &allow, 500);

out:
	if (ctx)
		ubus_free(ctx);

	return allow;
#endif
}

static char *
checksum(const char *applet, size_t sumlen, const char *file)
{
	pid_t pid;
	int r;
	int fds[2];
	static char chksum[65];

	if (pipe(fds))
		return NULL;

	switch ((pid = fork()))
	{
	case -1:
		return NULL;

	case 0:
		uloop_done();

		dup2(fds[1], 1);

		close(0);
		close(2);
		close(fds[0]);
		close(fds[1]);

		if (execl("/bin/busybox", "/bin/busybox", applet, file, NULL))
			return NULL;

		break;

	default:
		memset(chksum, 0, sizeof(chksum));
		r = read(fds[0], chksum, sumlen);

		waitpid(pid, NULL, 0);
		close(fds[0]);
		close(fds[1]);

		if (r < 0)
			return NULL;
	}

	return chksum;
}

static int
response(bool success, const char *message)
{
	char *chksum;
	struct stat s;

	printf("Status: 200 OK\r\n");
	printf("Content-Type: text/plain\r\n\r\n{\n");

	if (success)
	{
		if (!stat(st.filename, &s))
			printf("\t\"size\": %u,\n", (unsigned int)s.st_size);
		else
			printf("\t\"size\": null,\n");

		chksum = checksum("md5sum", 32, st.filename);
		printf("\t\"checksum\": %s%s%s,\n",
			chksum ? "\"" : "",
			chksum ? chksum : "null",
			chksum ? "\"" : "");

		chksum = checksum("sha256sum", 64, st.filename);
		printf("\t\"sha256sum\": %s%s%s\n",
			chksum ? "\"" : "",
			chksum ? chksum : "null",
			chksum ? "\"" : "");
	}
	else
	{
		if (message)
			printf("\t\"message\": \"%s\",\n", message);

		printf("\t\"failure\": [ %u, \"%s\" ]\n", errno, strerror(errno));

		if (st.filefd > -1 && st.filename)
			unlink(st.filename);
	}

	printf("}\n");

	return -1;
}

static int
failure(int code, int e, const char *message)
{
	printf("Status: %d %s\r\n", code, message);
	printf("Content-Type: text/plain\r\n\r\n");
	printf("%s", message);

	if (e)
		printf(": %s", strerror(e));

	printf("\n");

	return -1;
}

static int
filecopy(void)
{
	int len;
	char buf[READ_BLOCK];

	if (!st.filedata)
	{
		close(st.tempfd);
		errno = EINVAL;
		return response(false, "No file data received");
	}

	snprintf(buf, sizeof(buf), "/proc/self/fd/%d", st.tempfd);

	if (unlink(st.filename) < 0 && errno != ENOENT)
	{
		close(st.tempfd);
		return response(false, "Failed to unlink existing file");
	}

	if (linkat(AT_FDCWD, buf, AT_FDCWD, st.filename, AT_SYMLINK_FOLLOW) < 0)
	{
		if (lseek(st.tempfd, 0, SEEK_SET) < 0)
		{
			close(st.tempfd);
			return response(false, "Failed to rewind temp file");
		}

		st.filefd = open(st.filename, O_CREAT | O_TRUNC | O_WRONLY, 0600);

		if (st.filefd < 0)
		{
			close(st.tempfd);
			return response(false, "Failed to open target file");
		}

		while ((len = read(st.tempfd, buf, sizeof(buf))) > 0)
		{
			if (write(st.filefd, buf, len) != len)
			{
				close(st.tempfd);
				close(st.filefd);
				return response(false, "I/O failure while writing target file");
			}
		}

		close(st.filefd);
	}

	close(st.tempfd);

	if (chmod(st.filename, st.filemode))
		return response(false, "Failed to chmod target file");

	return 0;
}

static int
header_field(multipart_parser *p, const char *data, size_t len)
{
	st.is_content_disposition = !strncasecmp(data, "Content-Disposition", len);
	return 0;
}

static int
header_value(multipart_parser *p, const char *data, size_t len)
{
	size_t i, j;

	if (!st.is_content_disposition)
		return 0;

	if (len < 10 || strncasecmp(data, "form-data", 9))
		return 0;

	for (data += 9, len -= 9; len > 0 && (*data == ' ' || *data == ';'); data++, len--);

	if (len < 8 || strncasecmp(data, "name=\"", 6))
		return 0;

	for (data += 6, len -= 6, i = 1; i < len; i++)
	{
		if (data[i] == '"')
		{
			for (j = 1; j < sizeof(parts) / sizeof(parts[0]); j++)
				if (!strncmp(data, parts[j], i - 1))
					st.parttype = j;

			break;
		}
	}

	return 0;
}

static int
data_begin_cb(multipart_parser *p)
{
	if (st.parttype == PART_FILEDATA)
	{
		if (!st.sessionid)
			return response(false, "File data without session");

		if (!st.filename)
			return response(false, "File data without name");

		if (!session_access(st.sessionid, "file", st.filename, "write"))
			return response(false, "Access to path denied by ACL");

		st.tempfd = open("/tmp", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);

		if (st.tempfd < 0)
			return response(false, "Failed to create temporary file");
	}

	return 0;
}

static int
data_cb(multipart_parser *p, const char *data, size_t len)
{
	int wlen = len;

	switch (st.parttype)
	{
	case PART_SESSIONID:
		st.sessionid = datadup(data, len);
		break;

	case PART_FILENAME:
		st.filename = canonicalize_path(data, len);
		break;

	case PART_FILEMODE:
		st.filemode = strtoul(data, NULL, 8);
		break;

	case PART_FILEDATA:
		if (write(st.tempfd, data, len) != wlen)
		{
			close(st.tempfd);
			return response(false, "I/O failure while writing temporary file");
		}

		if (!st.filedata)
			st.filedata = !!wlen;

		break;

	default:
		break;
	}

	return 0;
}

static int
data_end_cb(multipart_parser *p)
{
	if (st.parttype == PART_SESSIONID)
	{
		if (!session_access(st.sessionid, "cgi-io", "upload", "write"))
		{
			errno = EPERM;
			return response(false, "Upload permission denied");
		}
	}
	else if (st.parttype == PART_FILEDATA)
	{
		if (st.tempfd < 0)
			return response(false, "Internal program failure");

#if 0
		/* prepare directory */
		for (ptr = st.filename; *ptr; ptr++)
		{
			if (*ptr == '/')
			{
				*ptr = 0;

				if (mkdir(st.filename, 0755))
				{
					unlink(st.tmpname);
					return response(false, "Failed to create destination directory");
				}

				*ptr = '/';
			}
		}
#endif

		if (filecopy())
			return -1;

		return response(true, NULL);
	}

	st.parttype = PART_UNKNOWN;
	return 0;
}

static multipart_parser *
init_parser(void)
{
	char *boundary;
	const char *var;

	multipart_parser *p;
	static multipart_parser_settings s = {
		.on_part_data        = data_cb,
		.on_headers_complete = data_begin_cb,
		.on_part_data_end    = data_end_cb,
		.on_header_field     = header_field,
		.on_header_value     = header_value
	};

	var = getenv("CONTENT_TYPE");

	if (!var || strncmp(var, "multipart/form-data;", 20))
		return NULL;

	for (var += 20; *var && *var != '='; var++);

	if (*var++ != '=')
		return NULL;

	boundary = malloc(strlen(var) + 3);

	if (!boundary)
		return NULL;

	strcpy(boundary, "--");
	strcpy(boundary + 2, var);

	st.tempfd = -1;
	st.filefd = -1;
	st.filemode = 0600;

	p = multipart_parser_init(boundary, &s);

	free(boundary);

	return p;
}

static int
main_upload(int argc, char *argv[])
{
	int rem, len;
	bool done = false;
	char buf[READ_BLOCK];
	multipart_parser *p;

	p = init_parser();

	if (!p)
	{
		errno = EINVAL;
		return response(false, "Invalid request");
	}

	while ((len = read(0, buf, sizeof(buf))) > 0)
	{
		if (!done) {
			rem = multipart_parser_execute(p, buf, len);
			done = (rem < len);
		}
	}

	multipart_parser_free(p);

	return 0;
}

static void
free_charp(char **ptr)
{
	free(*ptr);
}

#define autochar __attribute__((__cleanup__(free_charp))) char

static int
main_download(int argc, char **argv)
{
	char *fields[] = { "sessionid", NULL, "path", NULL, "filename", NULL, "mimetype", NULL };
	unsigned long long size = 0;
	char *p, buf[READ_BLOCK];
	ssize_t len = 0;
	struct stat s;
	int rfd;

	autochar *post = postdecode(fields, 4);

	if (!post)
		return failure(400, 0, "Invalid form data");

	if (!fields[1] || !session_access(fields[1], "cgi-io", "download", "read"))
		return failure(403, 0, "Download permission denied");

	/*
	 * Canonicalize the requested path before checking it against the session
	 * ACL and opening it. The rpcd ACL matcher uses fnmatch() without
	 * FNM_PATHNAME, so a "../" suffix would otherwise match an allowed glob
	 * prefix during the ACL check while open() resolves the embedded ".."
	 * and reaches a file outside of that prefix.
	 */
	autochar *path = fields[3] ? canonicalize_path(fields[3], strlen(fields[3])) : NULL;

	if (!path || !session_access(fields[1], "file", path, "read"))
		return failure(403, 0, "Access to path denied by ACL");

	if (stat(path, &s))
		return failure(404, errno, "Failed to stat requested path");

	if (!S_ISREG(s.st_mode) && !S_ISBLK(s.st_mode))
		return failure(403, 0, "Requested path is not a regular file or block device");

	for (p = fields[5]; p && *p; p++)
		if (!isalnum(*p) && !strchr(" ()<>@,;:[]?.=%-", *p))
			return failure(400, 0, "Invalid characters in filename");

	for (p = fields[7]; p && *p; p++)
		if (!isalnum(*p) && !strchr(" .;=/-", *p))
			return failure(400, 0, "Invalid characters in mimetype");

	rfd = open(path, O_RDONLY);

	if (rfd < 0)
		return failure(500, errno, "Failed to open requested path");

	if (S_ISBLK(s.st_mode))
		ioctl(rfd, BLKGETSIZE64, &size);
	else
		size = (unsigned long long)s.st_size;

	printf("Status: 200 OK\r\n");
	printf("Content-Type: %s\r\n", fields[7] ? fields[7] : "application/octet-stream");

	if (fields[5])
		printf("Content-Disposition: attachment; filename=\"%s\"\r\n", fields[5]);

	if (size > 0) {
		printf("Content-Length: %llu\r\n\r\n", size);
		fflush(stdout);

		while (size > 0) {
			len = sendfile(1, rfd, NULL, size);

			if (len == -1) {
				if (errno == ENOSYS || errno == EINVAL) {
					while ((len = read(rfd, buf, sizeof(buf))) > 0)
						fwrite(buf, len, 1, stdout);

					fflush(stdout);
					break;
				}

				if (errno == EINTR || errno == EAGAIN)
					continue;
			}

			if (len <= 0)
				break;

			size -= len;
		}
	}
	else {
		printf("\r\n");

		while ((len = read(rfd, buf, sizeof(buf))) > 0)
			fwrite(buf, len, 1, stdout);

		fflush(stdout);
	}

	close(rfd);

	return 0;
}

enum {
	CMD_CODE,
	CMD_STDERR,
	__CMD_MAX,
};

static const struct blobmsg_policy cmd_policy[__CMD_MAX] = {
	[CMD_CODE]   = { .name = "code", .type = BLOBMSG_TYPE_INT32 },
	[CMD_STDERR] = { .name = "stderr", .type = BLOBMSG_TYPE_STRING },
};

struct cmd_data {
	int code;
	int fd;
	bool redir_stderr;
	char *stderr_buf;
	char errmsg[256];
};

static void
cmd_reply_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct cmd_data *data = req->priv;
	struct blob_attr *tb[__CMD_MAX];
	char *p;

	if (!msg)
		return;

	blobmsg_parse(cmd_policy, __CMD_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[CMD_CODE])
		data->code = blobmsg_get_u32(tb[CMD_CODE]);

	if (tb[CMD_STDERR]) {
		if (data->redir_stderr)
			data->stderr_buf = strdup(blobmsg_get_string(tb[CMD_STDERR]));

		snprintf(data->errmsg, sizeof(data->errmsg), "%s",
			 blobmsg_get_string(tb[CMD_STDERR]));

		for (p = data->errmsg; *p; p++)
			if (*p == '\n' || *p == '\r')
				*p = ' ';
	}
}

static void
cmd_fd_cb(struct ubus_request *req, int fd)
{
	struct cmd_data *data = req->priv;

	data->fd = fd;
}

static int
main_backup(int argc, char **argv)
{
	uint32_t id;
	time_t now;
	int len;
	int r;
	void *array;
	char datestr[16] = { 0 };
	char hostname[64] = { 0 };
	char *fields[] = { "sessionid", NULL };
	struct ubus_context *ctx;
	struct ubus_request req;
	static struct blob_buf buf;
	struct cmd_data data = { .fd = -1 };

	autochar *post = postdecode(fields, 1);

	if (!post)
		return failure(400, 0, "Invalid form data");

	if (!fields[1] || !session_access(fields[1], "cgi-io", "backup", "read"))
		return failure(403, 0, "Backup permission denied");

	ctx = ubus_connect(NULL);

	if (!ctx || ubus_lookup_id(ctx, "file", &id))
		return failure(500, 0, "Failed to connect to ubus daemon");

	blob_buf_init(&buf, 0);
	blobmsg_add_string(&buf, "ubus_rpc_session", fields[1]);
	blobmsg_add_string(&buf, "command", "/sbin/sysupgrade");

	array = blobmsg_open_array(&buf, "params");
	blobmsg_add_string(&buf, NULL, "--create-backup");
	blobmsg_add_string(&buf, NULL, "-");
	blobmsg_close_array(&buf, array);

	blobmsg_add_u8(&buf, "stream", true);

	r = ubus_invoke_async(ctx, id, "exec", buf.head, &req);

	if (r == 0) {
		req.priv = &data;
		req.data_cb = cmd_reply_cb;
		req.fd_cb = cmd_fd_cb;
		r = ubus_complete_request(ctx, &req, 130000);
	}

	ubus_free(ctx);

	if (r)
		return failure(500, 0, "Failed to create backup");

	if (data.fd < 0)
		return failure(500, 0, "Backup streaming unsupported by rpcd");

	if (data.code)
		return failure(500, 0, data.errmsg[0] ? data.errmsg : "Backup failed");

	now = time(NULL);
	strftime(datestr, sizeof(datestr) - 1, "%Y-%m-%d", localtime(&now));

	if (gethostname(hostname, sizeof(hostname) - 1))
		sprintf(hostname, "OpenWrt");

	printf("Status: 200 OK\r\n");
	printf("Content-Type: application/x-targz\r\n");
	printf("Content-Disposition: attachment; "
	       "filename=\"backup-%s-%s.tar.gz\"\r\n\r\n", hostname, datestr);

	fflush(stdout);

	do {
		len = splice(data.fd, NULL, 1, NULL, READ_BLOCK, SPLICE_F_MORE);
	} while (len > 0 || (len == -1 && errno == EINTR));

	close(data.fd);

	return 0;
}


static const char *
lookup_executable(const char *cmd)
{
	size_t plen = 0, clen;
	static char path[PATH_MAX];
	char *search, *p;
	struct stat s;

	if (!cmd)
		return NULL;

	clen = strlen(cmd) + 1;

	if (!stat(cmd, &s) && S_ISREG(s.st_mode))
		return cmd;

	search = getenv("PATH");

	if (!search)
		search = "/bin:/usr/bin:/sbin:/usr/sbin";

	p = search;

	do {
		if (*p != ':' && *p != '\0')
			continue;

		plen = p - search;

		if ((plen + clen) >= sizeof(path))
			continue;

		strncpy(path, search, plen);
		sprintf(path + plen, "/%s", cmd);

		if (!stat(path, &s) && S_ISREG(s.st_mode))
			return path;

		search = p + 1;
	} while (*p++);

	return NULL;
}

static int
main_exec(int argc, char **argv)
{
	uint32_t id;
	int len;
	int r;
	int i;
	void *array;
	char *fields[] = { "sessionid", NULL, "command", NULL, "filename", NULL, "mimetype", NULL, "stderr", NULL };
	size_t exelen;
	const char *exe;
	char *p, **args;
	struct ubus_context *ctx;
	struct ubus_request req;
	static struct blob_buf buf;
	struct cmd_data data = { .fd = -1 };
	autochar *canon = NULL;

	autochar *post = postdecode(fields, 5);

	if (!post)
		return failure(400, 0, "Invalid form data");

	if (!fields[1] || !session_access(fields[1], "cgi-io", "exec", "read"))
		return failure(403, 0, "Exec permission denied");

	for (p = fields[5]; p && *p; p++)
		if (!isalnum(*p) && !strchr(" ()<>@,;:[]?.=%-", *p))
			return failure(400, 0, "Invalid characters in filename");

	for (p = fields[7]; p && *p; p++)
		if (!isalnum(*p) && !strchr(" .;=/-", *p))
			return failure(400, 0, "Invalid characters in mimetype");

	p = fields[9];
	if (p && p[0] == '1' && p[1] == '\0')
		data.redir_stderr = true;

	args = fields[3] ? parse_command(fields[3]) : NULL;

	if (!args)
		return failure(400, 0, "Invalid command parameter");

	/*
	 * Canonicalize the executable path before resolving it. rpcd matches
	 * the ACL against the canonical path, so this keeps the exec target and
	 * the ACL match in agreement.
	 */
	exelen = args[1] ? (size_t)(args[1] - args[0] - 1) : strlen(args[0]);
	canon = canonicalize_path(args[0], exelen);

	if (!canon) {
		free(args);
		return failure(400, 0, "Invalid command parameter");
	}

	/* Now split the command vector... */
	for (i = 1; args[i]; i++)
		args[i][-1] = 0;

	/* Find executable... */
	exe = lookup_executable(canon);

	if (!exe) {
		free(args);
		return failure(404, 0, "Executable not found");
	}

	ctx = ubus_connect(NULL);

	if (!ctx || ubus_lookup_id(ctx, "file", &id)) {
		free(args);
		return failure(500, 0, "Failed to connect to ubus daemon");
	}

	blob_buf_init(&buf, 0);
	blobmsg_add_string(&buf, "ubus_rpc_session", fields[1]);
	blobmsg_add_string(&buf, "command", exe);

	array = blobmsg_open_array(&buf, "params");
	for (i = 1; args[i]; i++)
		blobmsg_add_string(&buf, NULL, args[i]);
	blobmsg_close_array(&buf, array);

	blobmsg_add_u8(&buf, "stream", true);

	r = ubus_invoke_async(ctx, id, "exec", buf.head, &req);

	if (r == 0) {
		req.priv = &data;
		req.data_cb = cmd_reply_cb;
		req.fd_cb = cmd_fd_cb;
		r = ubus_complete_request(ctx, &req, 130000);
	}

	ubus_free(ctx);
	free(args);

	if (r) {
		free(data.stderr_buf);
		return failure(500, 0, "Failed to execute command");
	}

	if (data.fd < 0) {
		free(data.stderr_buf);
		return failure(500, 0, "Exec streaming unsupported by rpcd");
	}

	if (data.code) {
		free(data.stderr_buf);
		return failure(500, 0, data.errmsg[0] ? data.errmsg : "Command failed");
	}

	printf("Status: 200 OK\r\n");
	printf("Content-Type: %s\r\n",
	       fields[7] ? fields[7] : "application/octet-stream");

	if (fields[5])
		printf("Content-Disposition: attachment; filename=\"%s\"\r\n",
		       fields[5]);

	printf("\r\n");

	if (data.stderr_buf) {
		fwrite(data.stderr_buf, strlen(data.stderr_buf), 1, stdout);
		free(data.stderr_buf);
	}

	fflush(stdout);

	do {
		len = splice(data.fd, NULL, 1, NULL, READ_BLOCK, SPLICE_F_MORE);
	} while (len > 0 || (len == -1 && errno == EINTR));

	close(data.fd);

	return 0;
}

int main(int argc, char **argv)
{
	if (strstr(argv[0], "cgi-upload"))
		return main_upload(argc, argv);
	else if (strstr(argv[0], "cgi-download"))
		return main_download(argc, argv);
	else if (strstr(argv[0], "cgi-backup"))
		return main_backup(argc, argv);
	else if (strstr(argv[0], "cgi-exec"))
		return main_exec(argc, argv);

	return -1;
}
