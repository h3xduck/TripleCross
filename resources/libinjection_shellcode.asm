<nop>
push rax # 50
push rdx # 52
push rsi # 56
push rdi # 57
mov rax, <dlopen> # 48b8 <addr little endian> --> gdb: set *(int64_t *)0x402e95 = 0x7FFFF7D89560B848
jmp rax # ffe0  --> gdb: set *(int64_t *)0x402e9d = 0xe0ff0000

pop rdi 
pop rsi
pop rdx
pop rax
ret
