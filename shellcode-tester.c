/*
 *
 * http://www.thexploit.com/sploitdev/testing-your-shellcode-on-a-non-executable-stack-or-heap/
 *
 */
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

/*
 * create file "AAAA" as per fcreate.nasm file
 *
 */
char code[] = \
"\x31\xc0\x31\xc9\x50\x68"
"\x41\x41\x41\x41" // filename
"\x83\xc0\x08\x89\xe3\x66\xb9\xff\x01"
"\xcd\x80\x31\xc0\x31\xdb\x40\xcd\x80";
 
int main(int argc, char **argv) {
 
	void *ptr = mmap(0, sizeof(code),
		PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON
		| MAP_PRIVATE, -1, 0);
 
	if (ptr == MAP_FAILED) {
		 perror("mmap");
		 exit(-1);
	}

	printf("Shellcode: [%d]\n", sizeof(code));
 
	memcpy(ptr, code, sizeof(code));
	sc = ptr;
 
	sc();
 
	return 0;
}
