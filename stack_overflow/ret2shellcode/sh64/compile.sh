#!/bin/bash
nasm -f elf64 sh64.asm -o sh64.o
ld sh64.o -o sh64
objcopy -O binary sh64.o rawsh64


