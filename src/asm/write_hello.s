section .data
section .text

global _main
_main:

start:
    jmp trick

continue:
    pop rsi           
    mov rax, 0x2000004  ; sys_Write
    mov rdi, 1          ; stdout
    mov rdx, 14         ; Bytes to write
    syscall             
    mov rax, 0x2000001 
    mov rdi, 0          
    syscall             ; Exit

trick:
    call continue
    db "Hello World!", 0, 0  ; Str to write