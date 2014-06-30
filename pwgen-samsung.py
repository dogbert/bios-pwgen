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
                 30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l', 39: ';', 
                 44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm', 51: '.', 52: ',', 53: '/', 54:'<RSHIFT>', 55: '<NUMPAD/*>', 
                 59: '<F1>', 60: '<F2>', 61: '<F3>', 62: '<F4>', 63: '<F5>', 64: '<F6>', 65: '<F7>', 66: '<F8>', 67: '<F9>', 68: '<F9>', 87: '<F11>', 88: '<F12>',
                 71: '<NUMPAD7/HOME>', 72: '<NUMPAD8/UP>', 73: '<NUMPAD9/PGUP>', 74: '<NUMPAD->', 75: '<NUMPAD4/LEFT>', 76: '<NUMPAD5>',77: '<NUMPAD6/RIGHT>', 78: '<NUMPAD+>', 79: '<NUMPAD1/END>', 80: '<NUMPAD2/DOWN>', 81: '<NUMPAD3/PGDN>', 82: "<NUMPAD0/INS>", 83: "<NUMPAD./DEL>", 84: "<NUMPAD/DELIMITER>", 156: '<NUMPAD/ENTER>',
                  92: '<KP4/Left>',
                  1: '<ESCAPE>', 0xc7: '<HOME>',
                174: '<VOLDOWN>', 212: '<CAMERA>', 226: '<LAlt>', 227:'<LGUI>' }

def keyboardEncToAscii(inKey):
	out = ""
	pos = 0
	for c in inKey:
		pos += 1
		if c == 0: return out
		if c in keyboardDict: out += keyboardDict[c]
		else: out += "<U-0x%02x/%d>" % (c,c)
	return out

def decryptHash(hash, key, rotationMatrix):
	outhash = []
	for i in range(0, len(hash)):
		try:
			outhash.append(((hash[i] << (rotationMatrix[7*key+i])) & 0xFF) | (hash[i] >> (8-rotationMatrix[7*key+i])))
		except:
			return outhash
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

hexPwd = ""
asciiPwd = ""
for x in decryptHash(hash, key, rotationMatrix1):
	hexPwd += "%02x" % x
	asciiPwd += chr(x)
print "First Key"
print "Scancode Password: %s" % keyboardEncToAscii(decryptHash(hash, key, rotationMatrix1))
print "ASCII Password   : %s" % asciiPwd 
print "Hex Password     : %s" % hexPwd 
print ""

hexPwd = ""
asciiPwd = ""
for x in decryptHash(hash, key, rotationMatrix2):
	hexPwd += "%02x" % x
	asciiPwd += chr(x)
print "Second Key"
print "Scancode Password: %s" % keyboardEncToAscii(decryptHash(hash, key, rotationMatrix2))
print "ASCII Password   : %s" % asciiPwd 
print "Hex Password     : %s" % hexPwd 
print ""


if asciiPwd == "":
	print("The password could not be calculated. Bummer.")

if (os.name == 'nt'):
	print("Press a key to exit...")
	raw_input()
