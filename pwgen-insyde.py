#!/usr/bin/python

# Copyright 2011: dogbert <dogber1@gmail.com>
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
#
# This script generates master passwords which can be used to unlock
# the BIOS passwords of most Fujitsu Siemens laptops (Lifebook, Amilo etc.).
# You have to install python for running this script.

import os

def calcPassword(strHash):
	salt = 'Iou|hj&Z'

	pwd = ""
	for i in range(0, 8):
		b = ord(salt[i]) ^ ord(strHash[i])
		a = b
		a = (a * 0x66666667) >> 32
		a = (a >> 2) | (a & 0xC0)
		if ( a & 0x80000000 ):
			a += 1
		a *= 10
		pwd += str(b-a)
	return pwd


print("Master Password Generator for InsydeH2O BIOS (Acer, HP laptops)")
print("Copyright (C) 2009-2011 dogbert <dogber1@gmail.com>")
print("")
print("Enter three invalid passwords. You will receive a hash code consisting")
print("out of eight numbers ")
print("e.g. 03133610")
print("")
print("Please enter the hash: ")
inHash = raw_input().strip().replace('-', '')
password = calcPassword(inHash)
print("")
print("The master password is: " + password)
print("")
print("Please note that the password is encoded for US QWERTY keyboard layouts.")
if (os.name == 'nt'):
	print("Press a key to exit...")
	raw_input()

