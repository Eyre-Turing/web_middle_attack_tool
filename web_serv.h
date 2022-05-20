#ifndef WEB_SERV_H
#define WEB_SERV_H

/*
 * 该模块将接受客户端请求，并把内容（可篡改）发送给真正的服务端，然后把服务端响应（可篡改）发送给客户端
 * 设计理念：
 * 无论是收到客户端还是服务器的http信息，解析http头部，并且保存到结构体里
 * 解析完成后，进入交互函数，在这个函数里，可以篡改http头部，也可以篡改http请求体/响应体
 * http头部篡改完后，调用函数立即发送头部给被代理的对端，然后使用原始的socket读写操作发送请求体给被代理的对端
 */

#include <pthread.h> 
#include "cJSON.h"

#ifdef __cplusplus
extern "C"
{
#endif
// 请求
struct request
{
	char method[16];	// 请求方法，如：GET POST PUT 等
	char *url;		// 到被代理服务器的url参数，如：/index /#/ 等
	unsigned int urlsize;	// url 使用的储存空间大小，如果要篡改 url 内容，要看看新 url 的长度是否小于 urlsize（等于也不行，因为有\0）
					// 如果新url长度不小于urlsize，则要自行 realloc（总之，旧的空间要清理掉，否则内存泄露）
	char httpver[32];	// 协议版本，如：HTTP/1.1 等
	
	cJSON *header;	// 请求头，如：Content-Length Content-Type 等（由于cJSON支持键不区分大小写匹配，所以不转换大小写）
};

// 响应
struct response
{
	char httpver[32];	// 协议版本
	int code;		// 状态码，如：200 等
	char status[64];	// 状态，如：ok 等
	
	cJSON *header;	// 响应头
};

struct web_serv;

// 每次客户端和服务器之间发送的报文
struct content
{
	struct web_serv *web;
	struct request *req;	// 请求
	struct response *res;	// 响应，在send_reqhead前为NULL，send_reqhead后才创建
	
	int csockfd;	// 和客户端通信的套接字
	int ssockfd;	// 和服务端通信的套接字，在send_reqhead前为 -1
	
	pthread_t (*send_reqhead)(struct content *self);	// 发送请求头给服务端，这个函数执行后将创建响应
	void (*send_reshead)(struct content *self);	// 发送响应头给客户端
};

struct web_serv_t;

struct web_serv
{
	int domain;			// 类型，如：AF_INET
	unsigned int host;	// 监听的主机，即允许访问的IP，如：htonl(INADDR_ANY)
	unsigned short port;	// 监听的端口，如：80
	int backlog;

	char realhost[64];	// 真正的服务端（ip或域名）
	unsigned short realport;	// 真正的服务器端口

	struct web_serv_t *privates;	// 私有变量，这样写的作用是隐藏起来，不让用户直接操作

	void *chatvar;	// 用来给tamp2real和tamp2client保存数据，提供一个储存交互信息的变量

	int (*run)(struct web_serv *self);	// 启动，会阻塞当前进程
	void (*del)(struct web_serv *self);	// 销毁

	// 篡改并发送，在这两个函数都执行完后，将自动销毁ctx
	void (*tamp2real)(struct content *ctx);
	void (*tamp2client)(struct content *ctx);
};

struct web_serv *new_web_serv();	// 构造 web_serv 对象

// 默认的篡改并发送函数，即不做任何修改原封不动发送
void default_tamp2real(struct content *ctx);
void default_tamp2client(struct content *ctx);

#ifdef __cplusplus
}
#endif
#endif
