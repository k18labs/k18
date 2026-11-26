; sha.asm: SHA-256, HMAC and HKDF's expand, and the keys made with them. A part of os.asm, which includes it.
; keys: edi = key | iv from traffic secret ebx: 32 bytes of key (of which AES-128 uses
; 16), 12 of iv (+20 junk bytes: expand writes 32)
keys:
        pushad
        xor edx, edx
        mov esi, L_KEY
        call expand
        add edi, 32
        mov esi, L_IV
        call expand
        popad
        ret

; ----------------------------------------------------------------------------
; sha256: edi = SHA-256 of ecx bytes at esi (which are left alone)
sha256:
        pushad
        push rdi
        push rsi
        push rcx
        mov esi, HT
        mov edi, SH
        push 8
        pop rcx
        rep movsd
        pop rcx
        pop rsi
        mov edx, ecx
        call shaend
        pop rdi
        call shaout
        popad
        ret

; shaout: the hash whose state is at SH to edi (clobbers eax, ecx, esi; edi moves on)
shaout: mov esi, SH
        push 8
        pop rcx
.o:     lodsd
        bswap eax
        stosd
        loop .o
        ret

; shaend: the state at SH takes in the ecx bytes at rsi, which end a message of edx bytes: the
; whole blocks of them, then what is left with the padding (0x80, zeros, the length in
; bits), made in PADB. Clobbers all registers.
shaend: push rdx
        push rcx
        shr ecx, 6
        mov edi, SH
        call shablk
        pop rcx
        and ecx, 63
        mov edi, PADB
        rep movsb
        mov al, 0x80
        stosb
        lea ecx, [rdi+8+63-PADB] ; one block, or two if the length doesn't fit the first
        shr ecx, 6
        mov esi, ecx
        shl ecx, 6
        add ecx, PADB - 8
        sub ecx, edi
        xor eax, eax
        rep stosb
        pop rax
        shl rax, 3
        bswap rax
        stosq
        mov ecx, esi
        mov esi, PADB
        mov edi, SH
        ; fall through
        HOT 0x00FC00E4
; shablk: the state at rdi (8 dwords) takes in the ecx blocks of 64 bytes at rsi (rsi moves
; on; ecx may be 0). Clobbers rax, rcx, rdx, rbx, rbp, r8-r15.
; a-h are eax ebx ecx edx r8d-r11d; the 64 words of the message schedule are on the stack.
shablk: test ecx, ecx
        jz .ret
.blk:   push rcx
        sub rsp, 256
        mov eax, [rdi]
        mov ebx, [rdi+4]
        mov ecx, [rdi+8]
        mov edx, [rdi+12]
        mov r8d, [rdi+16]
        mov r9d, [rdi+20]
        mov r10d, [rdi+24]
        mov r11d, [rdi+28]
        xor r15d, r15d          ; round
.rnd:   cmp r15d, 16
        jae .sch
        mov r12d, [rsi+r15*4]
        bswap r12d
        jmp .w
.sch:   mov r12d, [rsp+r15*4-8] ; s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16]
        rorx r13d, r12d, 17
        rorx r14d, r12d, 19
        xor r13d, r14d
        shr r12d, 10
        xor r12d, r13d
        add r12d, [rsp+r15*4-28]
        mov r13d, [rsp+r15*4-60]
        rorx r14d, r13d, 7
        rorx ebp, r13d, 18
        xor r14d, ebp
        shr r13d, 3
        xor r14d, r13d
        add r12d, r14d
        add r12d, [rsp+r15*4-64]
.w:     mov [rsp+r15*4], r12d
        add r12d, [KT+r15*4]
        add r12d, r11d          ; h + k + w
        rorx r13d, r8d, 6
        rorx r14d, r8d, 11
        xor r13d, r14d
        rorx r14d, r8d, 25
        xor r13d, r14d
        add r12d, r13d          ; + S1(e)
        mov r13d, r10d
        xor r13d, r9d
        and r13d, r8d
        xor r13d, r10d
        add r12d, r13d          ; + ch(e, f, g): t1
        rorx r13d, eax, 2
        rorx r14d, eax, 13
        xor r13d, r14d
        rorx r14d, eax, 22
        xor r13d, r14d          ; S0(a)
        mov r14d, eax
        xor r14d, ebx
        mov ebp, ebx
        xor ebp, ecx
        and r14d, ebp
        xor r14d, ebx           ; maj(a, b, c) = ((a ^ b) & (b ^ c)) ^ b
        add r13d, r14d          ; t2
        mov r11d, r10d
        mov r10d, r9d
        mov r9d, r8d
        lea r8d, [rdx+r12]      ; e = d + t1
        mov edx, ecx
        mov ecx, ebx
        mov ebx, eax
        lea eax, [r12+r13]      ; a = t1 + t2
        inc r15d
        cmp r15b, 64
        jb .rnd
        add rsp, 256
        add [rdi], eax
        add [rdi+4], ebx
        add [rdi+8], ecx
        add [rdi+12], edx
        add [rdi+16], r8d
        add [rdi+20], r9d
        add [rdi+24], r10d
        add [rdi+28], r11d
        add rsi, 64
        pop rcx
        dec ecx
        jnz .blk
.ret:   ret

; hmac: edi = HMAC-SHA256(key = 32 bytes at ebx, ecx <= 64 bytes at esi)
hmac:
        pushad
        push rdi
        push rcx
        mov edi, HB+64
        rep movsb
        mov esi, ebx
        mov edi, HB
        mov cl, 64
.k:     xor eax, eax
        cmp cl, 32
        jbe .z
        lodsb
.z:     xor al, 0x36
        stosb
        loop .k
        pop rcx
        add ecx, 64
        mov esi, HB
        lea edi, [rsi+64]
        call sha256             ; inner hash
        mov cl, 64
.o:     xor byte [HB+rcx-1], 0x36 ^ 0x5c
        loop .o
        mov cl, 96
        pop rdi
        call sha256             ; outer hash
        popad
        ret

; expand: edi = HKDF-Expand-Label(secret ebx, label esi = {L, len, text}, context edx or 0), 32 bytes
expand:
        pushad
        push rdi
        mov edi, INFO
        mov al, 0
        stosb
        movsb                   ; output length
        lodsb
        add al, 6
        stosb
        push rsi
        mov esi, TLS13
        movsd
        movsw
        pop rsi
        sub al, 6
        movzx ecx, al
        rep movsb
        xor eax, eax
        test edx, edx
        jz .e
        mov al, 32
.e:     stosb
        jz .n
        mov esi, edx
        xchg eax, ecx
        rep movsb
.n:     mov al, 1
        stosb
        lea ecx, [rdi-INFO]
        mov esi, INFO
        pop rdi
        call hmac
        popad
        ret
