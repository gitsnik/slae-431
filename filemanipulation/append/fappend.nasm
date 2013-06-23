; Filename: fcreate.nasm
; Author: Gitsnik
; Website:  http://dracyrys.com
;
; Purpose:
;	file create syscall test. Create file "AAAA" with no
;	data inside it, open file for writing. Append if file
;	already exists.
;
;	handle = open( name,
;		O_RDWR | O_APPEND | O_CREAT,
;		S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH
;	);
;	write( handle, "Some text\n", 10 );
;	exit( 0 );
;
; Changes:
;
; Name of file is currently AAAA. If you change the push
;	update the add eax, 0x05 to be the proper size
;	of the file name.
;
; push as many bytes as you like instead of 0x42424242 for
; 	file contents. Just remember to re-calculate the
;	XOR for df 0x01FF to generate the proper length
;	of the string for write();
;

global _start			

section .text
_start:

	xor eax, eax
	xor ecx, ecx
	cdq

	push eax		; Null terminated.

	push 0x41414141		; Name of file.

	add eax, 0x05		; open syscall (5)
	mov ebx, esp		; ebx is about to point to...
	mov cx, 0x0442		; create flags
	mov dx, 0x01FF		; chmod flags (755)
	int 0x80

	xchg eax, ebx		; store file handle in ebx because it
				; is the first argument to write()
				; anyway so we might as well!

	xor eax, eax
	add eax, 0x04		; write syscall
	xor cx, 0x0448		; 0x0442 xor 0x0448 = 0x000a. The
				; alternative is to clear a register
				; and do the math on it to make our
				; newline. Urgh. ECX already has most
				; of what we want.
	push ecx
	push 0x42424242		; What we're writing
	mov ecx, esp
	xor dx, 0x01FA		; 0x01FF xor 0x01FA = 0x0005. DX
				; already contains the flags from
				; chmod.
	int 0x80

	; Exit
	xor eax, eax
	xor ebx, ebx
	inc eax
	int 0x80
