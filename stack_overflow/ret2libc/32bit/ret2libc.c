char buf2[40]="ret2libc is good";
void vul(){
    char buf[10];
    gets(buf);    
}
void main(){
    write(1,"hello",5);
    vul();
}

