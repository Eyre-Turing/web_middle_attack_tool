#include "web_serv.h"
#include <string.h>

int main()
{
	struct web_serv *virtual_web = new_web_serv();
	if (virtual_web == NULL) {
		return 1;
	}
	strcpy(virtual_web->realhost, "192.168.1.1");	// 这个ip一般是网关，如果用浏览器访问这个，一般是路由器管理页面
	virtual_web->realport = 80;
	virtual_web->run(virtual_web);
	virtual_web->del(virtual_web);
	return 0;
}
