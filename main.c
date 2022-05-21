#include "web_serv.h"
#include <stdio.h>
#include <string.h>

void usage(char *self)
{
	fprintf(stdout, 	"使用说明：\n"
				"  -h | --host   <服务器域名或IP>  设置真正的服务器的地址，默认：192.168.1.1\n"
				"  -p | --port   <服务器端口>      设置真正的服务器的端口，默认：80\n"
				"  -l | --listen <监听的端口>      设置本工具监听的端口，默认为：80\n"
				"  -? | --help                     显示本信息\n"
				"说明：\n"
				"  1、由于本工具要开启套接字连接监听，需要开启这方面的权限才可运行（当然可以直接使用root权限运行）\n"
				"  2、若服务器IP设置为空字符串，则表示以代理的方式运行（自动获取请求头的Host字端作为服务器地址）\n"
				"     如：%s -h \"\"\n",
				self);
}

int main(int argc, char *argv[])
{
	char realhost[128] = "192.168.1.1";	// 这个ip一般是网关，如果用浏览器访问这个，一般是路由器管理页面
	unsigned int realport = 80;
	unsigned int port = 80;
	unsigned int i;
	struct web_serv *virtual_web = new_web_serv();
	if (virtual_web == NULL) {
		return 1;
	}
	for (i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--host") == 0) {
			if (++i >= argc) {
				fprintf(stderr, "参数错误，%s参数需要指定服务器域名或IP\n", argv[i - 1]);
				return 1;
			}
			strcpy(realhost, argv[i]);
		} else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
			if (++i >= argc) {
				fprintf(stderr, "参数错误，%s参数需要指定服务器端口\n", argv[i - 1]);
				return 1;
			}
			sscanf(argv[i], "%u", &realport);
		} else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--listen") == 0) {
			if (++i >= argc) {
				fprintf(stderr, "参数错误，%s参数需要指定监听端口\n", argv[i - 1]);
				return 1;
			}
			sscanf(argv[i], "%u", &port);	// 这么写的原因是让输入变安全，virtual_web->port是unsigned short，很容易引起内存越界
		} else if (strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "--help") == 0) {
			usage(argv[0]);
			virtual_web->del(virtual_web);
			return 0;
		} else {
			fprintf(stderr, "不支持的参数%s\n", argv[i]);
			return 1;
		}
	}
	fprintf(stdout, "服务器地址：%s\n", realhost);
	fprintf(stdout, "服务器端口：%u\n", realport);
	fprintf(stdout, "监听的端口：%u\n", port);
	strcpy(virtual_web->realhost, realhost);
	virtual_web->realport = realport;
	virtual_web->port = port;
	if (virtual_web->run(virtual_web)) {
		usage(argv[0]);	// 给用户服务为什么会启动失败的提示
	}
	virtual_web->del(virtual_web);
	return 0;
}
