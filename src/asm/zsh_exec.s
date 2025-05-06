global _main

_main:
    xor rdx, rdx        ; Clear rdx register
    push rdx            ; Push NULL onto stack (String terminator)
    mov rbx, '/bin/zsh' ; Load '/bin/zsh' into rbx
    push rbx            ; Push '/bin/zsh' onto stack
    mov rdi, rsp        ; Set rdi to point to '/bin/zsh\0'
    xor rax, rax        ; Clear rax register
    mov ax, 0x632D      ; Load "-c" into lower 16 bits of rax
    push rax            ; Push "-c" onto stack
    mov rbx, rsp        ; Set rbx to point to "-c"
    push rdx            ; Push NULL onto stack
    jmp short dummy     ; Jump to label dummy

exec:
    push rbx            ; Push "-c" onto stack
    push rdi            ; Push '/bin/zsh' onto stack
    mov rsi, rsp        ; Set RSI to point to stack
    push 59             ; Push syscall number
    pop rax             ; Pop syscall number into rax
    bts rax, 25         ; Set 25th bit of rax (AT_FDCWD flag)
    syscall             ; Invoke syscall

dummy:
    call exec                   ; Call subroutine exec
    db 'open -a Calculator', 0       ; Define string
    push rdx                    ; Push NULL onto stack