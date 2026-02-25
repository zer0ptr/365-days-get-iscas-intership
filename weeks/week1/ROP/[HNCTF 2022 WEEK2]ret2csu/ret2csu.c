#include<stdio.h>
void vuln()
{
     char buf[0x100];
     write(1,"Input:\n",7);
     read(0,buf,0x200);
     write(1,"Ok.\n",4);
     return;
}
int main()
{
     setbuf(stdin,0);
     setbuf(stderr,0);
     setbuf(stdout,0);
     write(1,"Start Your Exploit!\n",20);
     vuln();
}
