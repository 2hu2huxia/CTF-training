#include <stdio.h>
#include <stdlib.h>
void vul(){
    char buf[10];
    read(0,buf,0x200);
}
void main(){
    write(1,"hello",5);
    vul();
}
