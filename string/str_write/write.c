#include<stdio.h>
int a = 20;
void main(){
char s[0x20];
read(0,s,0x20);
printf(s);
printf("a is %d\n",a);
}

