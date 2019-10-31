void main(){
	char *shellcode;
	read(0,shellcode,1000);
	void (*fptr)() = shellcode;
	fptr();
}

