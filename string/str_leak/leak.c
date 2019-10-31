#include<stdio.h>
void main(){
setvbuf(stdout,0,2,0);
printf("a");
char s[0x20];
read(0,s,0x20);
printf(s);
}

