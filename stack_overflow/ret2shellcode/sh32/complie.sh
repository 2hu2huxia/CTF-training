#!/bin/bash
nasm -f elf32 sh32.asm -o sh32.o
ld -m elf_i386 sh32.o -o sh32
objcopy -O binary sh32.o rawsh32

