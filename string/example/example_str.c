#include<stdio.h>
void init(){
    setvbuf(0,2,0);
    setvbuf(1,2,0);
}
void main(){
    init();
    char s[0x20];
    char *sh = "quit";

    while(1){
        memset(s,0,0x20);
        read(0,s,0x20);
        printf(s);
        if(strstr(s,"quit")){
            puts(sh);    
            exit(0);
            }
        }
}
