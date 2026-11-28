; aesgcm.asm: AES-128-GCM. A part of os.asm, which includes it.
; ----------------------------------------------------------------------------
        HOT 0x06006000          ; H-power setup, ks64, and seal_sb entry/exit branches
; seal: a TLS 1.3 record at rdi for the ecx bytes at rsi and, behind them inside it, the
; byte al that says what they are, under AES-128-GCM; key | iv at rbx (the key's 16
; bytes, 16 more, and 12), number edx. Returns rdi = the record's end.
; With CF set it is the other way round: the ecx bytes at rsi are what a record held between
; its header and its tag. They are decrypted to rdi, and behind them goes the tag that
; record should have had, for the caller to compare (rdi = behind that).
; A key stream 64 bytes at a time, xored straight onto what was given, and a tag over
; header | ciphertext | lengths, lined up in SB.
seal:   pushad
        sbb r12, r12            ; -1: decrypt (what we were given is the ciphertext)
        bswap edx               ; (the number goes on the nonce's last four bytes)
        mov edi, NB             ; the counter block: iv ^ number | counter
        mov rax, [rbx+32]
        stosq
        mov eax, [rbx+40]
        xor eax, edx
        stosd
        mov eax, 0x01000000     ; 1 for the tag, then 2, 3, ... (big-endian)
        stosd
        mov rsi, rbx
        call aeskey
        movdqa xmm7, [BSWAPM]
        movdqa xmm1, [NB]
        movdqa xmm4, xmm1
        pshufb xmm4, xmm7       ; reversed: the counter is a plain dword at the bottom
        push 1
        pop rax
        movd xmm0, eax
        paddd xmm4, xmm0        ; 2, for the first block of key stream
        pxor xmm0, xmm0
        push -62
        pop r8
        shl r8, 56
        movq xmm6, r8
        call aes4               ; H = AES(0), and what the tag's hash is masked with
        movdqa [TAGM], xmm1
        pshufb xmm0, xmm7       ; As a number (bytes reversed) H is kept times x: one bit
        movq rax, xmm0          ; to the left, and the bit that leaves at the top comes
        pextrq rdx, xmm0, 1     ; back as 0xC2..01; then H^2 through H^8, for eight blocks
        add rax, rax            ; at a time
        adc rdx, rdx
        sbb rcx, rcx
        sub rax, rcx
        and rcx, r8
        xor rdx, rcx
        movq xmm2, rax
        pinsrq xmm2, rdx, 1
        mov ebx, HTAB
        mov edi, ebx
        mov cl, 8
.hp:    movdqa [rdi], xmm2
        pshufd xmm0, xmm2, 0x4E
        pxor xmm0, xmm2
        movdqa [rdi+128], xmm0
        dec cl
        jz seal_sb
        movdqa xmm0, xmm2
        mov eax, 16
        call gh1
        add edi, 16
        jmp .hp

; seal_cached: encryption entry when sendrun seals another record under the same key.
; `bdrain -> prf` only reads packets and does not change RK or HTAB.
seal_cached:
        pushad
        sbb r12, r12
        bswap edx
        mov edi, NB
        mov rax, [rbx+32]
        stosq
        mov eax, [rbx+40]
        xor eax, edx
        stosd
        mov eax, 0x01000000
        stosd
        movdqa xmm7, [BSWAPM]
        movdqa xmm1, [NB]
        movdqa xmm4, xmm1
        pshufb xmm4, xmm7
        push 1
        pop rax
        movd xmm0, eax
        paddd xmm4, xmm0
        pxor xmm0, xmm0
        call aes4
        movdqa [TAGM], xmm1
        push -62
        pop r8
        shl r8, 56
        movq xmm6, r8
        jmp seal_sb

seal_sb: mov rdi, [rsp]         ; o
        mov rsi, [rsp+8]        ; m
        mov ebx, [rsp+40]       ; n
        mov rdx, r12
        pxor xmm0, xmm0
        mov ebp, SB             ; SB = header, 0 pad | ciphertext, 0 pad | lengths
        movdqa [rbp], xmm0
        mov dword [rbp], 0x030317
        lea eax, [rbx+rdx+17]   ; the record's length: with the tag, and with the byte we add
        xchg al, ah             ; if we do
        mov [rbp+3], ax
        test edx, edx
        jnz .go
        mov eax, [rbp]          ; encrypting: the record starts with that header
        stosd
        mov al, [rbp+4]
        stosb
.go:    add ebp, 16
.bulk:  cmp ebx, 64             ; 64 bytes at a time, in registers, while there are that many,
        jb .tail
        call ks64
        movdqu xmm5, [rsi]
        movdqu xmm8, [rsi+16]
        movdqu xmm9, [rsi+32]
        movdqu xmm10, [rsi+48]
        pxor xmm0, xmm5
        pxor xmm1, xmm8
        pxor xmm2, xmm9
        pxor xmm3, xmm10
        movdqu [rdi], xmm0
        movdqu [rdi+16], xmm1
        movdqu [rdi+32], xmm2
        movdqu [rdi+48], xmm3
        test edx, edx
        jnz .bdec
        movdqa xmm5, xmm0
        movdqa xmm8, xmm1
        movdqa xmm9, xmm2
        movdqa xmm10, xmm3
.bdec:  movdqa [rbp], xmm5
        movdqa [rbp+16], xmm8
        movdqa [rbp+32], xmm9
        movdqa [rbp+48], xmm10
        add rsi, 64
        add rdi, 64
        add ebp, 64
        sub ebx, 64
        jmp .bulk
.tail:  mov ecx, ebx            ; and the rest (at most 64 bytes, with the byte we add)
        push rdi
        mov edi, ebp
        rep movsb
        test edx, edx
        jnz .tlen
        mov al, [rsp+56]
        stosb
        inc ebx
.tlen:  pop rdi
        test ebx, ebx
        jz .done
        call ks64
        mov esi, KS
        movdqa [rsi], xmm0
        movdqa [rsi+16], xmm1
        movdqa [rsi+32], xmm2
        movdqa [rsi+48], xmm3
        xor ecx, ecx
.tx:    mov al, [rbp+rcx]
        xor al, [rsi+rcx]
        mov [rdi+rcx], al
        test edx, edx
        jnz .tn
        mov [rbp+rcx], al
.tn:    inc ecx
        cmp ecx, ebx
        jb .tx
        add rdi, rcx
        add ebp, ecx
.done:  pxor xmm0, xmm0
        movdqu [rbp], xmm0
        movdqu [rbp+16], xmm0
        lea ecx, [rbp-(SB+16)]
        lea eax, [rbp+15]
        and eax, -16            ; SB+16 is 16-aligned
        mov byte [rax+7], 40    ; the header's length and the ciphertext's, in bits,
        lea edx, [rcx*8]        ; big-endian
        bswap rdx
        mov [rax+8], rdx
        lea ebp, [rax+16-SB]
        shr ebp, 4              ; blocks to hash
        mov esi, SB
%ifdef HOST
        call haad               ; (the tests may have other bytes hashed than a header's)
%endif
        ; GHASH of the ebp blocks at SB, up to eight at a time: (y ^ b0) H^m ^ ... ^ b_{m-1} H
        ; in GF(2^128), reduced once.
        mov ebx, HTAB
        pxor xmm2, xmm2
.g8:    mov eax, 8
        cmp ebp, eax
        cmovb eax, ebp
        sub ebp, eax
        shl eax, 4
        movdqa xmm0, [rsi]
        pshufb xmm0, xmm7
        pxor xmm0, xmm2
        call gh1
        test ebp, ebp
        jnz .g8
        pshufb xmm2, xmm7
        pxor xmm2, [TAGM]
        movdqu [rdi], xmm2
        add rdi, 16
        mov [rsp], rdi
        popad
        ret

; ks64: the next 64 bytes of key stream, in xmm0-xmm3
ks64:   push 1
        pop rax
        movd xmm5, eax
        movdqa xmm0, xmm4
        paddd xmm4, xmm5
        movdqa xmm1, xmm4
        paddd xmm4, xmm5
        movdqa xmm2, xmm4
        paddd xmm4, xmm5
        movdqa xmm3, xmm4
        paddd xmm4, xmm5
        pshufb xmm0, xmm7
        pshufb xmm1, xmm7
        pshufb xmm2, xmm7
        pshufb xmm3, xmm7
        jmp aes4

        HOT 0xFFB39FFF
; gh1: xmm2 = sum of eax/16 products (xmm0, then blocks from rsi+16) with H^m .. H^1 at rbx,
; three multiplies each (Karatsuba), reduced once (xmm6 = 0xC2..00, xmm7 = BSWAPM)
gh1:    pxor xmm1, xmm1
        pxor xmm2, xmm2
        pxor xmm3, xmm3
        jmp .gm
.gn:    movdqa xmm0, [rsi]
        pshufb xmm0, xmm7
.gm:    add esi, 16             ; SB is below 4 GiB
        sub eax, 16
        movdqa xmm5, xmm0
        pclmulqdq xmm5, [rbx+rax], 0x00
        pxor xmm1, xmm5
        movdqa xmm5, xmm0
        pclmulqdq xmm5, [rbx+rax], 0x11
        pxor xmm2, xmm5
        pshufd xmm5, xmm0, 0x4E
        pxor xmm0, xmm5
        pclmulqdq xmm0, [rbx+rax+128], 0x00
        pxor xmm3, xmm0
        jnz .gn
        pxor xmm3, xmm1
        pxor xmm3, xmm2
        movdqa xmm0, xmm1
        pclmulqdq xmm0, xmm6, 0x00
        pshufd xmm1, xmm1, 0x4E
        pxor xmm1, xmm3
        pxor xmm1, xmm0
        movdqa xmm0, xmm1
        pclmulqdq xmm0, xmm6, 0x00
        pshufd xmm1, xmm1, 0x4E
        pxor xmm2, xmm1
        pxor xmm2, xmm0
        ret

        HOT 0xFFFF0F3D
; aeskey: the eleven round keys of the AES-128 key at rsi, to RK (clobbers eax, ecx, edi,
; xmm0-xmm2)
aeskey: movdqu xmm0, [rsi]
        mov edi, RK
        push 1                  ; the round constant: 1, and times x in GF(2^8) each round
        pop rax
        mov cl, 10
.k:     movdqa [rdi], xmm0
        add edi, 16
        aeskeygenassist xmm1, xmm0, 0
        pshufd xmm1, xmm1, 0xFF ; the last word, substituted and rotated, in all four words,
        movd xmm2, eax
        pshufd xmm2, xmm2, 0
        pxor xmm1, xmm2         ; with the round constant,
        movdqa xmm2, xmm0       ; on w0, w0 ^ w1, w0 ^ w1 ^ w2, ...
        pslldq xmm2, 4
        pxor xmm0, xmm2
        pslldq xmm2, 4
        pxor xmm0, xmm2
        pslldq xmm2, 4
        pxor xmm0, xmm2
        pxor xmm0, xmm1
        add al, al
        jnc .n
        xor al, 0x1B
.n:     dec cl
        jnz .k
        movdqa [rdi], xmm0
        ret

        HOT 0xFFFFF79F
; aes4: xmm0-xmm3 = AES of xmm0-xmm3 under the round keys at RK (clobbers eax, xmm5)
aes4:   mov eax, RK
        movdqa xmm5, [rax]
        pxor xmm0, xmm5
        pxor xmm1, xmm5
        pxor xmm2, xmm5
        pxor xmm3, xmm5
.r:     add eax, 16
        movdqa xmm5, [rax]
        aesenc xmm0, xmm5
        aesenc xmm1, xmm5
        aesenc xmm2, xmm5
        aesenc xmm3, xmm5
        cmp eax, RK + 144
        jb .r
        movdqa xmm5, [rax+16]
        aesenclast xmm0, xmm5
        aesenclast xmm1, xmm5
        aesenclast xmm2, xmm5
        aesenclast xmm3, xmm5
        ret

; aessingle: AES of xmm0 under RK (for CTR_DRBG's counter blocks).
aessingle:
        mov eax, RK
        movdqa xmm5, [rax]
        pxor xmm0, xmm5
        mov cl, 9
.r:     add eax, 16
        movdqa xmm5, [rax]
        aesenc xmm0, xmm5
        dec cl
        jnz .r
        movdqa xmm5, [rax+16]
        aesenclast xmm0, xmm5
        ret
