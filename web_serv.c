#include "web_serv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>

#define ONCE_READ	(1024 * 100)

#define DEBUG

#ifdef DEBUG
#define DEBUGINFO(fmt, args...)						\
do {									\
	time_t timep;							\
	struct tm *p;							\
	time(&timep);							\
	p = localtime(&timep);						\
	fprintf(stderr, "%d-%02d-%02d %02d:%02d:%02d ",			\
		1900+p->tm_year, 1+p->tm_mon, p->tm_mday,		\
		p->tm_hour, p->tm_min, p->tm_sec);			\
	fprintf(stderr, "%s:%d:[info] ", __FILE__, __LINE__);		\
	fprintf(stderr, fmt, ##args);					\
} while(0)
#else
#define DEBUGINFO(fmt, ...)
#endif

#define DEBUGERR(fmt, args...)						\
do {									\
	time_t timep;							\
	struct tm *p;							\
	time(&timep);							\
	p = localtime(&timep);						\
	fprintf(stderr, "%d-%02d-%02d %02d:%02d:%02d ",			\
		1900+p->tm_year, 1+p->tm_mon, p->tm_mday,		\
		p->tm_hour, p->tm_min, p->tm_sec);			\
	fprintf(stderr, "%s:%d:[error] ", __FILE__, __LINE__);		\
	fprintf(stderr, fmt, ##args);					\
} while(0)

struct web_serv_t
{
	int sockfd;
	struct sockaddr_in addr;
};

// 创建到真正的服务器的连接，成功则返回0
static int request_create(struct content *ctx)
{
	struct web_serv *web = ctx->web;
	char port[8];
	struct addrinfo hints = {
		.ai_socktype = SOCK_STREAM,
		.ai_family = web->domain
	};
	struct addrinfo *addr;
	sprintf(port, "%d", ctx->addr.hostport);
	if (getaddrinfo(ctx->addr.host, port, &hints, &addr)) {
		// 无法获取真正的服务器地址
		DEBUGERR("can not getaddrinfo. give up: %s\n", strerror(errno));
		return 1;	// 放弃这个包
	}
	ctx->ssockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	if (ctx->ssockfd < 0) {
		// 无法连接上服务端
		if (addr) {
			freeaddrinfo(addr);
			addr = NULL;
		}
		DEBUGERR("can not create socket. give up: %s\n", strerror(errno));
		return 2;	// 放弃这个包
	}
	if (connect(ctx->ssockfd, addr->ai_addr, addr->ai_addrlen) < 0) {
		close(ctx->ssockfd);
		if (addr) {
			freeaddrinfo(addr);
			addr = NULL;
		}
		DEBUGERR("can not connect to real server. give up: %s\n", strerror(errno));
		return 3;
	}
	freeaddrinfo(addr);
	return 0;
}

// 读请求（或响应）头，并且解析成结构体，成功返回0，失败返回非0值
// sockfd 是读取的套接字
// parseline 是解析请求行（或响应行），请求行和响应行的解析方式不一样，所以用一个回调，回调的第3个参数为返回，因为要分配空间，所有为二级指针
// parseheader 是解析请求头（或响应头），第3个参数为返回，因为直接使用 parseline 分配的空间，所以一级指针即可
// parseline 和 parseheader 返回0时表示能正常解析，返回非0值表示解析失败
static int create_head(int sockfd,
				int (*parseline)(char *pbuf, unsigned int *len, void **res),
				int (*parseheader)(char *pbuf, unsigned int *len, void *res),
				void **res)
{
	char buf[1];
	char *nptr;
	unsigned int mul = 1;
	unsigned int pos = 0;
	unsigned int len = 0;
	unsigned int flag = 0;	// 当前已经连续读取 \r\n 的个数
	unsigned int rline = 0;	// 已读取完成的行数
	unsigned int pline = 0;	// 已解析完成的行数，rline 和 pline 的区别在于是否读完\n
	int n;
	char *msg;
	msg = (char *) malloc(ONCE_READ * mul);
	if (msg == NULL) {
		DEBUGERR("malloc msg failed. give up\n");
		return -1;
	}
	while ((n = read(sockfd, buf, 1)) > 0) {	// 读完空行后停止
		len += n;
		if (len >= ONCE_READ * mul) {
			++mul;
			nptr = (char *) realloc(msg, ONCE_READ * mul);
			if (nptr) {
				msg = nptr;
			} else {	// 扩容失败
				DEBUGERR("realloc failed. give up\n");
				free(msg);
				return 1;
			}
		}
		memcpy(msg + pos, buf, n);
		msg[len] = '\0';
		if (buf[0] == '\n') {
			flag++;
			rline++;
		} else if (buf[0] != '\r') {
			flag = 0;
		}
		if (flag == 2) {	// 说明读取完空行了（下面的内容已经是请求体或响应体了）
			break;
		}
		if (rline > pline && buf[0] != '\n') {	// 说明上次循环已经读取完成\n了，这次读取的已经不是\n了，即\n解析完成，msg开头必没有\n
			pline++;
		}
		if (pline) {
			// 解析头部信息
			if (parseheader(msg, &len, *res)) {
				DEBUGERR("parseheader failed. pbuf: %s\n", msg);
				free(msg);
				return 2;
			}
		} else if (rline == 1) {
			// 解析首行
			if (parseline(msg, &len, res)) {
				DEBUGERR("parseline failed. pbuf: %s\n", msg);
				free(msg);
				return 3;
			}
		}
		pos = len;
	}
	if (n < 0) {
		DEBUGERR("read error: %s\n", strerror(errno));
	}
	free(msg);
	return 0;
}

static struct request *new_request()
{
	struct request *ret = (struct request *) malloc(sizeof(struct request));
	if (ret == NULL) {
		DEBUGERR("malloc failed. give up\n");
		return NULL;
	}
	memset(ret->method, 0, sizeof(ret->method));
	ret->url = NULL;
	ret->urlsize = 0;
	memset(ret->httpver, 0, sizeof(ret->httpver));
	ret->header = cJSON_CreateObject();
	return ret;
}

static void delete_request(struct request *self)
{
	if (!self) {
		return ;
	}
	free(self->url);
	cJSON_Delete(self->header);
	free(self);
}

static struct response *new_response()
{
	struct response *ret = (struct response *) malloc(sizeof(struct response));
	if (ret == NULL) {
		DEBUGERR("malloc failed. give up\n");
		return NULL;
	}
	memset(ret->httpver, 0, sizeof(ret->httpver));
	ret->code = 0;
	memset(ret->status, 0, sizeof(ret->status));
	ret->header = cJSON_CreateObject();
	return ret;
}

static void delete_response(struct response *self)
{
	if (!self) {
		return ;
	}
	cJSON_Delete(self->header);
	free(self);
}

static int parseline_request(char *pbuf, unsigned int *len, void **res)
{
	/*
	 * 要解析的内容都在 pbuf 里
	 * 格式：
	 * method url httpver
	 * 示例：
	 * GET /admin_ui/rdx/core/images/close.png HTTP/1.1
	 */
	unsigned int i = 0;
	unsigned int catcnt;
	struct request *res_t;
	*res = new_request();
	if (*res == NULL) {
		DEBUGERR("new_request failed. give up\n");
		return -1;
	}
	res_t = (struct request *) *res;
	for (catcnt = 0; i < *len && *pbuf != ' '; ++pbuf, ++i, ++catcnt) {
		if (catcnt >= sizeof(res_t->method) - 1) {		// -1 是因为最后要结束符 '\0'
			DEBUGERR("strncat too long. give up\n");
			delete_request(res_t);
			return 1;
		}
		strncat(res_t->method, pbuf, 1);
	}
	if (i >= *len) {
		DEBUGERR("parse request line failed. can not find space(\\s). give up\n");
		delete_request(res_t);
		return 1;
	}
	++pbuf;
	++i;
	res_t->url = (char *) malloc(*len);
	if (res_t->url == NULL) {
		DEBUGERR("malloc failed. give up\n");
		delete_request(res_t);
		return 2;
	}
	memset(res_t->url, 0, *len);
	res_t->urlsize = *len;
	for (catcnt = 0; i < *len && *pbuf != ' '; ++pbuf, ++i, ++catcnt) {
		if (catcnt >= res_t->urlsize - 1) {
			DEBUGERR("strncat too long. give up\n");
			delete_request(res_t);
			return 1;
		}
		strncat(res_t->url, pbuf, 1);
	}
	if (i >= *len) {
		DEBUGERR("parse request line failed. can not find space(\\s). give up\n");
		delete_request(res_t);
		return 3;
	}
	++pbuf;
	++i;
	for (catcnt = 0; i < *len && *pbuf != '\r' && *pbuf != '\n' && *pbuf != '\0'; ++pbuf, ++i, ++catcnt) {
		if (catcnt >= sizeof(res_t->httpver) - 1) {
			DEBUGERR("strncat too long. give up\n");
			delete_request(res_t);
			return 1;
		}
		strncat(res_t->httpver, pbuf, 1);
	}
	if (i >= *len) {
		DEBUGERR("parse request line failed. can not read EOF. give up\n");
		delete_request(res_t);
		return 4;
	}
	*len = 0;	// 解析完成，把使用了的缓冲长度弄成0，给后续数据读取复用空间
	return 0;
}

static int parseline_response(char *pbuf, unsigned int *len, void **res)
{
	/*
	 * 格式：
	 * httpver code status
	 * 示例：
	 * HTTP/1.0 200 OK
	 */
	unsigned int i = 0;
	unsigned int catcnt;
	struct response *res_t;
	*res = new_response();
	if (*res == NULL) {
		DEBUGERR("new_response failed. give up\n");
		return -1;
	}
	res_t = (struct response *) *res;
	for (catcnt = 0; i < *len && *pbuf != ' '; ++pbuf, ++i, ++catcnt) {
		if (catcnt >= sizeof(res_t->httpver) - 1) {
			DEBUGERR("strncat too long. give up\n");
			delete_response(res_t);
			return 1;
		}
		strncat(res_t->httpver, pbuf, 1);
	}
	if (i >= *len) {
		DEBUGERR("parse response line failed. can not find space(\\s). give up\n");
		delete_response(res_t);
		return 1;
	}
	++pbuf;
	++i;
	for (catcnt = 0; i < *len && *pbuf != ' '; ++pbuf, ++i, ++catcnt) {
		if (catcnt >= 10) {	// int 的极限
			DEBUGERR("response too big. give up\n");
			delete_response(res_t);
			return 1;
		}
		res_t->code *= 10;
		res_t->code += pbuf[0] - '0';
	}
	if (i >= *len) {
		DEBUGERR("parse response line failed. can not find space(\\s). give up\n");
		delete_response(res_t);
		return 2;
	}
	++pbuf;
	++i;
	for (catcnt = 0; i < *len && *pbuf != '\r' && *pbuf != '\n' && *pbuf != '\0'; ++pbuf, ++i, ++catcnt) {
		if (catcnt >= sizeof(res_t->status) - 1) {
			DEBUGERR("strncat too long. give up\n");
			delete_response(res_t);
			return 1;
		}
		strncat(res_t->status, pbuf, 1);
	}
	if (i >= *len) {
		DEBUGERR("parse response line failed. can not read EOF. give up\n");
		delete_response(res_t);
		return 4;
	}
	*len = 0;
	return 0;
}

static int parseheader(char *pbuf, unsigned int *len, cJSON *header)
{
	/*
	 * 数据都保存到pbuf里，一行一个
	 * 示例：
	 * Content-Type: text/plain
	 * Content-Length: 100
	 * 但是，pbuf里保存的是全部的，每读取到一个字符，都会调用该函数
	 * 所以，需要想办法分割，并且利用pbuf提供的缓冲空间来操作
	 * 这里使用的办法是：
	 * 判断是否读取到\n，读取到即认为获取到了一个请求头或响应头
	 * 然后根据第一个冒号，把键和值分开，再保存到json里
	 */
	unsigned int i = 0;
	char *key;
	char *value;
	if (pbuf[(*len) - 1] != '\n') {	// 没有读取完一行，继续读取
		return 0;
	}
	key = (char *) malloc(*len);
	if (key == NULL) {
		DEBUGERR("malloc key failed. give up\n");
		return -1;
	}
	memset(key, 0, *len);
	value = (char *) malloc(*len);
	if (value == NULL) {
		DEBUGERR("malloc value failed. give up\n");
		free(key);
		return -1;
	}
	memset(value, 0, *len);
	for (; i < *len && *pbuf != ':'; ++pbuf, ++i) {	// 读取键
		// if (*pbuf >= 'A' && *pbuf <= 'Z') {	// 转小写
		// 	*pbuf ^= 32;
		// }
		strncat(key, pbuf, 1);
	}
	if (i >= *len) {
		DEBUGERR("parse header key failed. can not find colon(:). give up\n");
		free(key);
		free(value);
		return 1;
	}
	++pbuf;
	++i;
	for (; i < *len && *pbuf == ' '; ++pbuf, ++i);	// 去除值首空，注意这里有分号，没有循环体
	for (; i < *len && *pbuf != '\r' && *pbuf != '\n'; ++pbuf, ++i) {	// 读取值
		strncat(value, pbuf, 1);
	}
	if (cJSON_AddStringToObject(header, key, value) == NULL) {	// 插入到json里
		DEBUGERR("cJSON_AddStringToObject failed. give up\n");
		free(key);
		free(value);
		return 2;
	}
	*len = 0;
	free(key);
	free(value);
	return 0;
}

static int parseheader_request(char *pbuf, unsigned int *len, void *res)
{
	struct request *res_t = (struct request *) res;
	int ret = parseheader(pbuf, len, res_t->header);
	if (ret) {
		delete_request(res_t);
	}
	return ret;
}

static int parseheader_response(char *pbuf, unsigned int *len, void *res)
{
	struct response *res_t = (struct response *) res;
	int ret = parseheader(pbuf, len, res_t->header);
	if (ret) {
		delete_response(res_t);
	}
	return ret;
}

static pthread_t content_send_reqhead(struct content *self)
{
	pthread_t resp_thr;
	int i;
	char *head_msg;	// 头部信息
	char *nptr;
	unsigned int head_msg_len = 0;
	unsigned int mul = 1;
	cJSON *item;

	head_msg = (char *) malloc(ONCE_READ * mul);
	if (head_msg == NULL) {
		DEBUGERR("malloc failed. give up\n");
		_exit(-1);
	}

	DEBUGINFO("make request line\n");
	DEBUGINFO("%s %s %s\n", self->req->method, self->req->url, self->req->httpver);

	// 构造请求行
	while (ONCE_READ * mul <= strlen(self->req->method) + 1 + strlen(self->req->url) + 1 + strlen(self->req->httpver) + 2) {
		++mul;
		nptr = (char *) realloc(head_msg, ONCE_READ * mul);
		if (nptr == NULL) {
			DEBUGERR("realloc failed. give up\n");
			_exit(-1);
		}
		head_msg = nptr;
	}
	strcpy(head_msg, self->req->method);
	strcat(head_msg, " ");
	strcat(head_msg, self->req->url);
	strcat(head_msg, " ");
	strcat(head_msg, self->req->httpver);
	strcat(head_msg, "\r\n");
	head_msg_len = strlen(self->req->method) + 1 + strlen(self->req->url) + 1 + strlen(self->req->httpver) + 2;

	DEBUGINFO("make request header\n");

	// 构造请求头
	for (i = 0; i < cJSON_GetArraySize(self->req->header); ++i) {
		item = cJSON_GetArrayItem(self->req->header, i);
		DEBUGINFO("header.%s = %s\n", item->string, item->valuestring);
		while (ONCE_READ * mul <= head_msg_len + strlen(item->string) + 2 + strlen(item->valuestring) + 2) {
			++mul;
			nptr = (char *) realloc(head_msg, ONCE_READ * mul);
			if (nptr == NULL) {
				DEBUGERR("realloc failed. give up\n");
				_exit(-1);
			}
			head_msg = nptr;
		}
		strcat(head_msg, item->string);
		strcat(head_msg, ": ");
		strcat(head_msg, item->valuestring);
		strcat(head_msg, "\r\n");
		head_msg_len += strlen(item->string) + 2 + strlen(item->valuestring) + 2;
	}

	DEBUGINFO("make empty line\n");

	// 构造空行
	while (ONCE_READ * mul <= head_msg_len + 2) {
		++mul;
		nptr = (char *) realloc(head_msg, ONCE_READ * mul);
		if (nptr == NULL) {
			DEBUGERR("realloc failed. give up\n");
			_exit(-1);
		}
		head_msg = nptr;
	}
	strcat(head_msg, "\r\n");
	head_msg_len += 2;

	head_msg[head_msg_len] = '\0';

	if (request_create(self)) {	// 创建连接
		DEBUGERR("create request failed. give up\n");
		_exit(1);
	}

	DEBUGINFO("send head message\n");

	write(self->ssockfd, head_msg, head_msg_len);

	free(head_msg);

	if (pthread_create(&resp_thr, NULL, self->web->tamp2client, self)) {	// 篡改响应线程启动
		DEBUGERR("create pthread failed: %s\n", strerror(errno));
		_exit(2);
	}
	return resp_thr;
}

static void content_send_reshead(struct content *self)
{
	int i;
	cJSON *item;
	char codestr[16] = {0};

	DEBUGINFO("send response line\n");
	DEBUGINFO("%s %d %s\n", self->res->httpver, self->res->code, self->res->status);

	// 发送响应行
	write(self->csockfd, self->res->httpver, strlen(self->res->httpver));
	write(self->csockfd, " ", 1);
	sprintf(codestr, "%d", self->res->code);
	write(self->csockfd, codestr, strlen(codestr));
	write(self->csockfd, " ", 1);
	write(self->csockfd, self->res->status, strlen(self->res->status));
	write(self->csockfd, "\r\n", 2);

	DEBUGINFO("send response header\n");

	// 发送响应头
	for (i = 0; i < cJSON_GetArraySize(self->res->header); ++i) {
		item = cJSON_GetArrayItem(self->res->header, i);
		DEBUGINFO("header.%s = %s\n", item->string, item->valuestring);
		write(self->csockfd, item->string, strlen(item->string));
		write(self->csockfd, ": ", 2);
		write(self->csockfd, item->valuestring, strlen(item->valuestring));
		write(self->csockfd, "\r\n", 2);
	}

	DEBUGINFO("send empty line\n");

	write(self->csockfd, "\r\n", 2);	// 发送空行
}

static void acpt(struct web_serv *self)
{
	unsigned int clen;
	int csockfd;
	struct sockaddr_in caddr;
	pid_t pid;
	struct request *req = NULL;
	struct content *ctx = NULL;
	signal(SIGCHLD, SIG_IGN);	// 子进程退出后，直接推给init进程为它收尸
	while (1) {
		clen = sizeof(caddr);
		csockfd = accept(self->privates->sockfd, (struct sockaddr *) &caddr, &clen);
		if (pid = fork()) {
			close(csockfd);	// 关闭客户端套接字句柄，将该句柄所有权交给子进程
		} else {
			DEBUGINFO("client connected, message relay start\n");
			close(self->privates->sockfd);	// 关闭服务端套接字句柄，子进程只处理请求，无需监听
			if (create_head(csockfd, parseline_request, parseheader_request, &req)) {	// 解析请求头
				DEBUGERR("create_head failed. give up\n");
				close(csockfd);
				_exit(1);
			}
			ctx = (struct content *) malloc(sizeof(struct content));
			if (ctx == NULL) {
				DEBUGERR("malloc failed. give up\n");
				close(csockfd);
				_exit(-1);
			}

			ctx->web = self;
			ctx->csockfd = csockfd;
			ctx->ssockfd = -1;	// 开始先置空，因为刚开始还没有勾搭上真正的服务端
			ctx->req = req;
			ctx->res = NULL;	// 开始先置空，因为刚开始还没有勾搭上真正的服务端，更没有响应数据
			ctx->send_reqhead = content_send_reqhead;
			ctx->send_reshead = content_send_reshead;

			strcpy(ctx->addr.host, self->realhost);
			ctx->addr.hostport = self->realport;
			strcpy(ctx->addr.client, inet_ntoa(caddr.sin_addr));
			ctx->addr.clientport = caddr.sin_port;
			DEBUGINFO("[message addrinfo] host       = %s\n", ctx->addr.host);
			DEBUGINFO("[message addrinfo] hostport   = %u\n", ctx->addr.hostport);
			DEBUGINFO("[message addrinfo] client     = %s\n", ctx->addr.client);
			DEBUGINFO("[message addrinfo] clientport = %u\n", ctx->addr.clientport);

			self->tamp2real(ctx);	// 篡改，并且发送信息
			delete_request(ctx->req);
			delete_response(ctx->res);
			close(csockfd);
			if (ctx->ssockfd >= 0) {
				close(ctx->ssockfd);
			}
			DEBUGINFO("end of message relay\n");
			_exit(0);
		}
	}
}

static int web_serv_run(struct web_serv *self)
{
	int ret = 0;
	if ((self->privates->sockfd = socket(self->domain, SOCK_STREAM, 0)) < 0) {
		DEBUGERR("create socket failed: %s\n", strerror(errno));
		return -1;
	}
	memset(&(self->privates->addr), 0, sizeof(self->privates->addr));
	self->privates->addr.sin_family = self->domain;
	self->privates->addr.sin_addr.s_addr = self->host;
	self->privates->addr.sin_port = htons(self->port);
	if (ret = bind(self->privates->sockfd, (struct sockaddr *) &(self->privates->addr), sizeof(self->privates->addr))) {
		DEBUGERR("bind failed: %s\n", strerror(errno));
		close(self->privates->sockfd);
		self->privates->sockfd = -1;
		return ret;
	}
	if (ret = listen(self->privates->sockfd, self->backlog)) {
		DEBUGERR("listen failed: %s\n", strerror(errno));
		close(self->privates->sockfd);
		self->privates->sockfd = -1;
		return ret;
	}
	DEBUGINFO("run web service\n");
	acpt(self);
	return 0;
}

static void delete_web_serv(struct web_serv *self)
{
	if (self->privates->sockfd >= 0) {
		close(self->privates->sockfd);
		self->privates->sockfd = -1;
	}
	free(self->privates);
	free(self);
}

void default_tamp2real(struct content *ctx)
{
	/*
	 * 这种函数，需要先篡改好请求头，然后调用 ctx->send_reqhead(self) 后即会创建子线程做真正的服务端给客户端发送消息的中继
	 * 然后本函数内循环把请求体发给服务端即可（既然是本函数内发送的，当然是想怎么篡改就怎么篡改了）
	 * 
	 * 本函数为默认的函数，默认不对任何数据进行修改，只是做个示例
	 */
	struct web_serv *self = ctx->web;
	int n;
	char buf[ONCE_READ + 1];
	pthread_t resp_thr;		// 执行响应的子线程
	struct timeval tv_timeout = {	// 设置等待超时
		.tv_sec = 1,
		.tv_usec = 0
	};
	cJSON *item;

	// 修改 ctx->req->header 即可篡改请求头，下面举个例子，但是我没打算改这些，所以注释掉了
	// item = cJSON_GetObjectItem(ctx->req->header, "host");	// cJSON是可以不区分大小写获取的，所以host和Host效果是一样的
	// if (item) {
	// 	item = NULL;
	// 	cJSON_DeleteItemFromObject(ctx->req->header, "host");
	// 	cJSON_AddStringToObject(ctx->req->header, "Host", self->realhost);	// 篡改请求头Host为真服务器的ip
	// }
	if (strcmp(ctx->addr.host, "") == 0) {
		// 如果目标服务器IP地址为空，则根据请求头Host字端的值设置服务器IP
		item = cJSON_GetObjectItem(ctx->req->header, "host");
		if (item == NULL) {
			DEBUGERR("unknow server\'s ip addr. give up\n");
			return ;
		}
		strcpy(ctx->addr.host, item->valuestring);
	}
	resp_thr = ctx->send_reqhead(ctx);	// 在这行代码执行完之后，服务端给客户端发送消息的线程就会启动，self->tamp2client 就开始执行了

	// 下面把请求体内容都发给服务端，下面代码都这么明示了，要篡改请求体知道怎么篡改了吧（笑）
	setsockopt(ctx->csockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));
	while ((n = recv(ctx->csockfd, buf, ONCE_READ, 0)) != 0) {
		if (n < 0) {
			if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {	// 超时
				n = recv(ctx->ssockfd, buf, ONCE_READ, MSG_PEEK);	// 判断中继对端是否断开
				if (n == 0 || (n < 0 && errno != EWOULDBLOCK)) {	// n=0表示断开；n<0时errno=EWOULDBLOCK表示无数据但是没有断开，所以此时errno!=EWOULDBLOCK表示断开
					break;
				}
				continue;
			}
			break;	// 对端异常
		}
		buf[n] = '\0';
		write(ctx->ssockfd, buf, n);
	}

	pthread_join(resp_thr, NULL);	// 等待响应结束，不等待的话，发完请求本进程就 gg 了
}

void default_tamp2client(struct content *ctx)
{
	// 我懒得重复注释了，和上面的 default_tamp2real 一个道理
	struct web_serv *self = ctx->web;
	int n;
	char buf[ONCE_READ + 1];
	struct timeval tv_timeout = {	// 设置等待超时
		.tv_sec = 1,
		.tv_usec = 0
	};

	if (create_head(ctx->ssockfd, parseline_response, parseheader_response, &(ctx->res))) {	// 获取响应头
		return ;
	}

	// 发送响应头
	ctx->send_reshead(ctx);

	// 发送响应体
	setsockopt(ctx->ssockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));
	while ((n = recv(ctx->ssockfd, buf, ONCE_READ, 0)) != 0) {
		if (n < 0) {
			if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {	// 超时
				n = recv(ctx->csockfd, buf, ONCE_READ, MSG_PEEK);	// 判断中继对端是否断开
				if (n == 0 || (n < 0 && errno != EWOULDBLOCK)) {	// n=0表示断开；n<0时errno=EWOULDBLOCK表示无数据但是没有断开，所以此时errno!=EWOULDBLOCK表示断开
					break;
				}
				continue;
			}
			break;	// 对端异常
		}
		buf[n] = '\0';
		write(ctx->csockfd, buf, n);
	}
}

struct web_serv *new_web_serv()
{
	struct web_serv_t *privates = (struct web_serv_t *) malloc(sizeof(struct web_serv_t));
	if (privates == NULL) {
		DEBUGERR("malloc privates failed. give up\n");
		return NULL;
	}
	privates->sockfd = -1;
	struct web_serv ret_t = {
		.domain = AF_INET,
		.host = htonl(INADDR_ANY),
		.port = 80,
		.backlog = 5,
		.realhost = "",
		.realport = 0,
		.privates = privates,
		.run = web_serv_run,
		.del = delete_web_serv,
		.tamp2real = default_tamp2real,
		.tamp2client = default_tamp2client
	};
	struct web_serv *ret = (struct web_serv *) malloc(sizeof(struct web_serv));
	if (!ret) {
		DEBUGERR("malloc failed. give up\n");
		free(privates);
		return NULL;
	}
	memcpy(ret, &ret_t, sizeof(struct web_serv));
	return ret;
}
