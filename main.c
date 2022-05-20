#include "web_serv.h"
#include <stdio.h>
#include <string.h>

void usage()
{
	fprintf(stdout, 	"使用说明：\n"
				"  -h | --host <服务器域名或IP>  设置真正的服务器的地址，默认：192.168.1.1\n"
				"  -p | --port <服务器端口>      设置真正的服务器的端口，默认：80\n"
				"  -? | --help                   显示本信息\n");
}

int main(int argc, char *argv[])
{
	char realhost[64] = "192.168.1.1";	// 这个ip一般是网关，如果用浏览器访问这个，一般是路由器管理页面
	unsigned int realport = 80;
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
		} else if (strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "--help") == 0) {
			usage();
			virtual_web->del(virtual_web);
			return 0;
		} else {
			fprintf(stderr, "不支持的参数%s\n", argv[i]);
			return 1;
		}
	}
	fprintf(stdout, "服务器地址：%s\n", realhost);
	fprintf(stdout, "服务器端口：%u\n", realport);
	strcpy(virtual_web->realhost, realhost);
	virtual_web->realport = realport;
	virtual_web->run(virtual_web);
	virtual_web->del(virtual_web);
	return 0;
}
