#!/usr/bin/python

# Copyright 2009-2010:  dogbert <dogber1@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

import os

rotationMatrix1 = [7, 1, 5, 3, 0, 6, 2, 5, 2, 3, 0, 6, 1, 7, 6, 1, 5, 2, 7, 1, 0, 3, 7, 6, 1, 0, 5, 2, 1, 5, 7, 3, 2, 0, 6]
rotationMatrix2 = [1, 6, 2, 5, 7, 3, 0, 7, 1, 6, 2, 5, 0, 3, 0, 6, 5, 1, 1, 7, 2, 5, 2, 3, 7, 6, 2, 1, 3, 7, 6, 5, 0, 1, 7]

keyboardDict = {  2: '1',  3: '2',  4: '3',  5: '4',  6: '5',  7: '6',  8: '7',  9: '8', 10: '9', 11: '0',
                 16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p',
                 30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l', 
                 44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm' }

def keyboardEncToAscii(inKey):
	out = ""
	for c in inKey:
		if c == 0: return out
		if c in keyboardDict: out += keyboardDict[c]
		else: return ""
	return out

def decryptHash(hash, key, rotationMatrix):
	outhash = []
	for i in range(0, len(hash)):
		outhash.append(((hash[i] << (rotationMatrix[7*key+i])) & 0xFF) | (hash[i] >> (8-rotationMatrix[7*key+i])))
	return outhash

print("Master Password Generator for Samsung laptops (12 hexadecimal digits version)")
print("Copyright (C) 2009-2010 dogbert <dogber1@gmail.com>")
print("")
print("After entering the wrong password for the third time, you will receive a")
print("hexadecimal code from which the password can be calculated,")
print("e.g. 07088120410C0000")
print("")
print("Please enter the code: ")
code = raw_input()
hash = []
for i in range(1, len(code) // 2):
	hash.append(int(code[2*i]+code[2*i+1],16))
key = int(code[0:2], 16) % 5

password = keyboardEncToAscii(decryptHash(hash, key, rotationMatrix1))
if password == "":
	password = keyboardEncToAscii(decryptHash(hash, key, rotationMatrix2))
if password == "":
	print("The password could not be calculated. Bummer.")
else:
	print("The password is: " + password)

if (os.name == 'nt'):
	print("Press a key to exit...")
	raw_input()
