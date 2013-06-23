; Filename: fcreate.nasm
; Author: Gitsnik
; Website:  http://dracyrys.com
;
; Purpose:
;	file create syscall test. Create file "AAAA" with no
;	data inside it.
;
;	28 bytes
;	char shellcode[] = \
;		"\x31\xc0\x31\xc9\x50\x68"
;		"\x41\x41\x41\x41" // filename
;		"\x83\xc0\x08\x89\xe3\x66\xb9\xff\x01"
;		"\xcd\x80\x31\xc0\x31\xdb\x40\xcd\x80";
;
;	Note that the exit call at the end is necessary
;	to prevent the demo shellcode from erroring out.
;

global _start			

section .text
_start:

	xor eax, eax
	xor ecx, ecx
	push eax	; Null terminated.

	push 0x41414141	; Name of file.

	add eax, 0x08	; creat syscall
	mov ebx, esp	; ebx is about to point to...
	mov cx, 0x01FF	; chmod flags (755)
	int 0x80

	xor eax, eax
	xor ebx, ebx
	inc eax
	int 0x80
