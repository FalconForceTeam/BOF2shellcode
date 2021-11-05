; Based on http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html and https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/

extern go
global alignstack

segment .text

alignstack:
    push rsi                 
    mov rsi, rsp              
    and  rsp, 0FFFFFFFFFFFFFFF0h 
    sub  rsp, 020h
    call go      
    mov rsp, rsi 
    pop rsi   
    ret       
