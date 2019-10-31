#include <stdio.h>
#include <stdlib.h>

char *shell = "/bin/sh";

void vul(){
    char buf[100];
    gets(buf);

}
int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);
    vul();
}

