#include<stdio.h>
char buf2[40]="ret2libc is good";
void vul(){
    char buf[10];
    gets(buf);    
}
void main(){
    setvbuf(stdout,0,2,0);
//    setvbuf(stdin,0,2,0);
    write(1,"hello",5);
    vul();
}

