#include <stdio.h>
#include <stdlib.h>

int main(){
	char buf[200];
	setvbuf(stdout,0,2,0);
	printf("This is an example binary:\n");
	gets(buf);
	puts("welcome to challenge");
}
