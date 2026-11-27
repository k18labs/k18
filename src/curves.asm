; curves.asm: X25519 and ECDSA on P-256. A part of os.asm, which includes it.
; ----------------------------------------------------------------------------
; Elliptic curves: 256-bit arithmetic mod m in four limbs of 64 bits, weakly reduced, in a
; 16-register machine. tools/ec.py has the programs, the bounds that make this safe, and a
; model of all of it. rbp points at the field in use (F_...; all three are built at boot).
; None of this branches on, or indexes with, anything secret.
R_E0    equ REGS + 0*32         ; a table entry lands here; the client's u; the hash to sign
R_E1    equ REGS + 1*32         ; our public key after xdh's XPOST
R_X     equ REGS + 3*32         ; the point at hand; the shared secret; r after `sign`
R_Y     equ REGS + 4*32         ; s after `sign`
R_Z     equ REGS + 5*32
R_T0    equ REGS + 7*32
R_T1    equ REGS + 8*32
R_ONE   equ REGS + 12*32
R_A24   equ REGS + 13*32
R_D     equ REGS + 14*32
R_C     equ REGS + 15*32
%define fadd19 fas.a19        ; add and subtract mod 2^255 - 19, without `fas` asking which
%define fsub19 fas.s19

        HOT 0x03000000
; vm: run the program at rsi in the field at rbp. Returns rsi = after the program; clobbers
; all else but rbp. In the image a program is 2 bytes per operation (a << 4 | b, op << 4 |
; dst; a zero byte ends it: tools/ec.py); what runs is what boot made of that (`ecinit`,
; from XP on, X_name for each): the three registers' addresses and the operation less 1,
; a dword each, and a zero dword to end it.
vm:     mov edi, [rsi]
        test edi, edi
        jz .end
        mov ebx, [rsi+8]
        mov ecx, [rsi+12]       ; 0 add, 1 subtract, 2 multiply, 3 multiply (a has one
        push rsi                ; limb), 4 square
        mov esi, [rsi+4]
        cmp ecx, 2
        je .mul
        ja .more
        call fas
        jmp .next
.mul:   call fmul
.next:  pop rsi
        add rsi, 16
        jmp vm
.more:  cmp ecx, 4
        je .sqr
        call fmul1
        jmp .next
.sqr:   call fsqr
        jmp .next
.end:   add rsi, 4
        ret


; xdh: our X25519 key share for the secret E (clamped as in RFC 7748: a multiple of 8, so
; every point of small order makes R_X = 0) to rdi (which moves on 32 bytes), and R_X = the
; secret we share with the client whose key share is at rsi.
; Our share is E times the base point: 64 additions from the table TABE. The secret is E
; times the client's point: the ladder. Both end in a division, which they share.
; (Keeps the eight old registers, as do `sign` and the hashes: r8-r15 are scratch.)
xdh:    pushad
        mov ebp, F25519
        push rdi
        push rsi
        mov esi, X_INITED
        call vm
        mov esi, TABE
        push 96
        pop rcx
        mov edx, X_MADDED
        mov ebx, E
        and byte [rbx], 0xF8
        and byte [rbx+31], 0x7F
        or byte [rbx+31], 0x40
        call comb
        mov esi, X_KEYED
        call vm
        pop rsi
        mov edi, R_E0
        push 4
        pop rcx
        rep movsq               ; the client's u,
        and byte [rdi-1], 0x7F  ; which has 255 bits (RFC 7748)
        mov esi, X_INIT25519
        call vm
        xor edx, edx            ; The ladder, from the top bit down. The two points change
        mov ecx, 254            ; RFC 7748: the clamped scalar's top bit is bit 254.
.l:     JUMPH 5                 ; (every jump of this loop is kept off the 32-byte boundaries
        test cl, 63             ; where it stands, by JUMPH: the routine may begin anywhere)
        jnz .step
        JUMPH 5
        call bdrain             ; (four times on the way: see `drain`)
.step:  xor eax, eax
        bt [E], ecx
        adc eax, eax
        push rax
        push rcx
        xor edx, eax
        JUMPH 5
        call cswap
%include "step.inc"             ; (the step: tools/ec.py's STEP25519, as calls)
        pop rcx
        pop rdx
        JUMPH 8
        dec ecx
        jns .l
        call cswap
        mov esi, X_XPRE
        call vm
        push rsi                ; (XPOST follows XPRE)
        mov esi, R_T0
        call inv
        pop rsi
        call vm
        pop rdi
        mov esi, R_E1
        call freeze
        mov [rsp], rdi
        mov edi, R_X
        mov esi, edi
        call freeze
        popad
        ret

        HOT 0xFFFFFFF8
; cswap: swap (X, Y) with (Z, T) if edx = 1, not if edx = 0 (clobbers rcx, rdx, rdi,
; xmm0-xmm3)
cswap:  neg edx
        movd xmm0, edx
        pshufd xmm0, xmm0, 0    ; all ones, or nothing
        mov edi, R_X
        push 4
        pop rcx
.s:     movdqa xmm1, [rdi]
        movdqa xmm2, [rdi+64]
        movdqa xmm3, xmm1
        pxor xmm3, xmm2         ; what the two differ in, if they are to be swapped
        pand xmm3, xmm0
        pxor xmm1, xmm3
        pxor xmm2, xmm3
        movdqa [rdi], xmm1
        movdqa [rdi+64], xmm2
        add edi, 16              ; R_X is below 4 GiB
        dec ecx
        jnz .s
        ret

; freeze: the number at rsi (four limbs, below 2^256) mod 2^255 - 19, to rdi (which moves on)
freeze: mov r8, [rsi]
        mov r9, [rsi+8]
        mov r10, [rsi+16]
        mov r11, [rsi+24]
        mov rax, r11            ; bit 255 is worth 19
        shr rax, 63
        imul eax, eax, 19
        btr r11, 63
        add r8, rax
        adc r9, 0
        adc r10, 0
        adc r11, 0              ; below 2^255 + 19 now. If that plus 19 reaches 2^255, it was
        mov rax, r8             ; 2^255 - 19 or more, and that sum less 2^255 is the answer
        mov rcx, r9
        mov rdx, r10
        mov r12, r11
        add rax, 19
        adc rcx, 0
        adc rdx, 0
        adc r12, 0
        btr r12, 63
        cmovc r8, rax
        cmovc r9, rcx
        cmovc r10, rdx
        cmovc r11, r12
        ; fall through
; put4: the four limbs r8-r11 to rdi (which moves on)
put4:    mov [rdi], r8
        mov [rdi+8], r9
        mov [rdi+16], r10
        mov [rdi+24], r11
        add rdi, 32
        ret

; sign: an ECDSA signature of the 32-byte hash at rsi under our key: r to R_X, s = (hash +
; r d) / k to R_Y, both canonical. The half that needs no hash, r = x(k G) and 1 / k for a
; fresh random nonce k, is taken from a stock that `stock` makes: each is used once.
sign:   pushad
        push rsi
.more:  mov eax, [POOLN]
        test eax, eax
        jnz .have
        call stock
        call bdrain
        jmp .more
.have:  dec eax
        mov [POOLN], eax
        shl eax, 5
        lea esi, [rax+POOLR]
        mov edi, R_X
        push 4
        pop rcx
        rep movsq
        lea esi, [rax+POOLK]
        mov edi, R_T1
        mov cl, 4
        rep movsq
        mov ebp, FN256
        pop rsi
        mov edi, R_E0
        mov cl, 32              ; the hash as a number
.rev:   mov al, [rsi+rcx-1]
        stosb
        loop .rev
        mov esi, X_SIGN
        call vm
        popad
        ret

; A per-processor AES-128 CTR_DRBG state, in space not used by the network tables.
DRBGK   equ NV + 224           ; Key, then V; AES-128 CTR_DRBG, no derivation function
DRBGV   equ DRBGK + 16
DRBGN   equ DRBGK + 32         ; Generate requests since the last reseed
DRBGR   equ DRBGK + 36         ; 0 until initialized
DRBGT   equ DRBGK + 48         ; Update's 32-byte temporary value
DRBGS   equ DRBGK + 80         ; 256 bits from the hardware during init/reseed

; Increment the 128-bit, big-endian CTR_DRBG V.
hctr_inc:
        mov rax, [DRBGV+8]
        bswap rax
        inc rax
        bswap rax
        mov [DRBGV+8], rax
        jnz .done
        mov rax, [DRBGV]
        bswap rax
        inc rax
        bswap rax
        mov [DRBGV], rax
.done:  ret

; CTR_DRBG_Update: AES(K, V+1) | AES(K, V+2), xor the optional provided_data, and
; replace K and V. RSI is the provided_data pointer (0 means 32 zero bytes).
hctr_update:
        push rdi
        push rsi
        push rcx
        push r8
        push r9
        mov r9, rsi
        mov esi, DRBGK
        call aeskey
        jmp hctr_update_core
hctr_update_keyed:
        push rdi
        push rsi
        push rcx
        push r8
        push r9
        mov r9, rsi
hctr_update_core:
        call hctr_inc
        movdqa xmm0, [DRBGV]
        call aessingle
        movdqa [DRBGT], xmm0
        call hctr_inc
        movdqa xmm0, [DRBGV]
        call aessingle
        movdqa [DRBGT+16], xmm0
        movdqa xmm0, [DRBGT]
        test r9, r9
        jz .zero1
        movdqu xmm1, [r9]
        pxor xmm0, xmm1
.zero1: movdqa [DRBGK], xmm0
        movdqa xmm0, [DRBGT+16]
        test r9, r9
        jz .zero2
        movdqu xmm1, [r9+16]
        pxor xmm0, xmm1
.zero2: movdqa [DRBGV], xmm0
        pxor xmm0, xmm0
        movdqa [DRBGT], xmm0
        movdqa [DRBGT+16], xmm0
        pop r9
        pop r8
        pop rcx
        pop rsi
        pop rdi
        ret

; Seed or reseed from 256 fresh RDRAND bits. On first use K and V start at zero;
; later calls use the existing state, as CTR_DRBG_Reseed requires.
drbg_seed:
        push rdi
        push rcx
        cmp dword [DRBGR], 0
        jne .state
        mov qword [DRBGK], 0
        mov qword [DRBGK+8], 0
        mov qword [DRBGV], 0
        mov qword [DRBGV+8], 0
.state: mov edi, DRBGS
        push 4
        pop rcx
        call rand_hw
        mov eax, [CPUN]         ; separate AP streams even if a broken source clones CPU output
        xor [DRBGS+28], eax
        mov esi, DRBGS
        call hctr_update
        mov dword [DRBGN], 0
        mov dword [DRBGR], 1
        pxor xmm0, xmm0
        movdqa [DRBGS], xmm0
        movdqa [DRBGS+16], xmm0
        pop rcx
        pop rdi
        ret

; Generate ecx qwords to rdi. V advances once per 16 output bytes; Update with
; zero provided_data after every request. AES round keys are rebuilt from the new K.
hctr_generate:
        push r8
        mov r8d, ecx
        push rdi
        mov esi, DRBGK
        call aeskey
        pop rdi
.block: call hctr_inc
        movdqa xmm0, [DRBGV]
        call aessingle
        movq [rdi], xmm0
        add rdi, 8
        dec r8d
        jz .update
        pextrq rax, xmm0, 1
        mov [rdi], rax
        add rdi, 8
        dec r8d
        jnz .block
.update:
        xor esi, esi
        call hctr_update_keyed
        xor ecx, ecx
        pop r8
        ret

; rand: ecx qwords to rdi from the per-processor DRBG. The hardware source seeds it and
; is checked on every reseed. A request is reseeded after at most 64 Generate calls.
rand:   sub rsp, 64            ; preserve the vector registers, as the old RDRAND loop did
        movdqu [rsp], xmm0
        movdqu [rsp+16], xmm1
        movdqu [rsp+32], xmm2
        movdqu [rsp+48], xmm5
        cmp dword [DRBGR], 0
        je .seed
        cmp dword [DRBGN], 64
        jb .gen
.seed:  call drbg_seed
.gen:   call hctr_generate
        inc dword [DRBGN]
        movdqu xmm0, [rsp]
        movdqu xmm1, [rsp+16]
        movdqu xmm2, [rsp+32]
        movdqu xmm5, [rsp+48]
        mov qword [rsp], 0
        mov qword [rsp+8], 0
        mov qword [rsp+16], 0
        mov qword [rsp+24], 0
        mov qword [rsp+32], 0
        mov qword [rsp+40], 0
        mov qword [rsp+48], 0
        mov qword [rsp+56], 0
        add rsp, 64
        ret

; Raw hardware entropy is used only to seed/reseed the DRBG. Each qword is compared with
; the last hardware value; a repeated value means stop rather than continue with weak state.
rand_hw:
%ifdef WXTEST
%if WXTEST = 13                 ; emulate an RDRAND instruction which never succeeds
.stalled:
        pause
        jmp .stalled
%endif
%endif
        rdrand rax
        jnc rand_hw
%ifdef WXTEST
%if WXTEST = 8                  ; (make WXTEST=8, for tools/wxtest.sh: a generator that is
        or rax, -1              ; stuck at all ones)
%endif
%endif
        cmp rax, [RLAST]
        je .stuck
        mov [RLAST], rax
        stosq
        loop rand_hw
        ret
.stuck: ud2

; stock: one step towards the next NPOOL nonces k with their r = x(k G) (POOLR) and R^2 / k
; (POOLK): either one more k and its k G, or, when all are there, the divisions: two for
; all of them (`binv`). The polling loop does a step whenever it has nothing else to do and
; the stock is empty, `sign` as many as it takes. Clobbers everything.
; k G is 64 additions from the table TABP, which holds (j + 1) 16^i G: starting from 2^255 G
; (an entry itself), for the nibbles of k - 2^255 - 0x1111...1 (ec.py says why). k is 256
; random bits, whatever number that is.
stock:  mov ebx, [POOLFILL]
        cmp ebx, NPOOL * 32
        je .all
        lea edi, [rbx+POOLK]
        push 4
        pop rcx
        call rand
%ifdef HOST
        mov al, [HKSET]         ; (the tests choose the nonce that is used first: HKSET = 1;
        mov esi, HK             ; or all of them: 2, and then they are at HK in the order
        cmp al, 2               ; they are made in, the one used first last)
        jne .one
        add esi, ebx
        jmp .mine
.one:   cmp ebx, (NPOOL - 1) * 32
        jne .k
        test al, al
        jz .k
.mine:  lea edi, [rbx+POOLK]
        mov cl, 4
        rep movsq
.k:
%endif
        add dword [POOLFILL], 32
        push rbx
        mov ebp, FN256
        lea esi, [rbx+POOLK]
        mov edi, KD
        mov ebx, KOFFV
        inc ecx
        call fas
        mov ebp, FP256
        mov esi, TABP + (63 * 16 + 7) * 64
        mov edi, R_E0
        push 8
        pop rcx
        rep movsq
        mov esi, X_INIT256
        call vm
        mov esi, TABP
        push 64
        pop rcx
        mov edx, X_MADD256
        mov ebx, KD
        call comb
        pop rbx
        lea edi, [rbx+POOLR]    ; X and Z of k G: r = X / Z^2 is still to come
        mov esi, R_X
        push 4
        pop rcx
        rep movsq
        lea edi, [rbx+POOLZ]
        mov esi, R_Z
        mov cl, 4
        rep movsq
        ret
.all:   mov ebp, FP256
        mov ebx, POOLZ
        call binv
        xor ebx, ebx
.r:     push rbx
        lea esi, [rbx+POOLZ]
        mov edi, R_T1
        push 4
        pop rcx
        rep movsq
        lea esi, [rbx+POOLR]
        mov edi, R_X
        mov cl, 4
        rep movsq
        mov esi, X_FIN256
        call vm
        pop rbx
        lea edi, [rbx+POOLR]
        mov esi, R_X
        push 4
        pop rcx
        rep movsq
        add ebx, 32
        cmp ebx, NPOOL * 32
        jb .r
        mov ebp, FN256
        mov ebx, POOLK
        call binv
        mov dword [POOLN], NPOOL
        and dword [POOLFILL], 0
        ret

; binv: each of the NPOOL numbers at rbx (four limbs) becomes what `inv` makes of it in the
; field at rbp, with one `inv` for all: of their product (Montgomery's trick). POOLP gets
; the products of the first 1, 2, 3, ... of them; then, from the last one down, the
; inverse of the product so far times the product of those before is that one's inverse,
; and times the number itself the inverse of the product before. Clobbers everything.
binv:   mov esi, ebx
        mov edi, POOLP
        push 4
        pop rcx
        rep movsq
        mov ebx, esi
.f:     lea rsi, [rdi-32]
        call fmul
        add ebx, 32
        add edi, 32
        cmp edi, POOLP + NPOOL * 32
        jb .f
        lea esi, [rdi-32]
        push rbx
        call inv
        pop rbx
        mov edx, POOLP + (NPOOL - 1) * 32
.b:     sub ebx, 32
        sub edx, 32
        push rbx
        push rdx
        mov ebx, edx
        mov edi, R_T0
        mov esi, R_T1
        call fmul
        mov rbx, [rsp+8]
        mov edi, R_T1
        mov esi, edi
        call fmul
        mov edi, ebx
        mov esi, R_T0
        push 4
        pop rcx
        rep movsq
        pop rdx
        pop rbx
        cmp edx, POOLP
        ja .b
        lea edi, [rbx-32]
        mov esi, R_T1
        push 4
        pop rcx
        rep movsq
        ret

        HOT 0xE0F80E0F
; comb: to the point in X.. are added, for i = 0 .. 63, entry number (nibble i of the 32 bytes
; at rbx) of the 16 entries (ecx bytes each) of window i of the table at rsi, each by the
; program at rdx. Clobbers all but rbp.
comb:   xor eax, eax
.w:     push rax
        push rdx
        push rbx
        mov edx, eax
        shr edx, 1
        movzx edx, byte [rbx+rdx]
        test al, 1              ; (which nibble of the byte: no secret)
        jz .lo
        shr edx, 4
.lo:    and edx, 15
        call select             ; (leaves rsi at the next window)
        push rsi
        push rcx
        mov rsi, [rsp+24]
        call vm
        pop rcx
        pop rsi
        pop rbx
        pop rdx
        pop rax
        inc eax
        cmp al, 64
        jb .w
        ret

ecinit: mov edi, BSWAPM         ; (and what GHASH needs: how pshufb reverses 16 bytes)
        mov al, 15
.bs:    stosb
        dec al
        jns .bs
        mov esi, INIT25519      ; the programs, unpacked for `vm`: they follow each other
        mov edi, XP             ; in the image
        mov dl, NPROG
.op:    lodsb
        movzx ebx, al
        test ebx, ebx
        jz .pe
        lodsb
        movzx ecx, al
        call .reg               ; dst,
        mov eax, ebx
        shr eax, 4
        call .reg               ; a,
        xchg eax, ebx
        call .reg               ; b,
        xchg eax, ecx
        shr eax, 4
        dec eax
        stosd                   ; and what to do with them
        jmp .op
.pe:    xchg eax, ebx
        stosd
        dec dl
        jnz .op
        mov edi, F25519 + F_M
        or rax, -1
        push 4
        pop rcx
        rep stosq
        mov byte [rdi-32], -38
        add edi, FSIZE - 32     ; p of P-256: 2^64 - 1, 2^32 - 1, 0, 2^64 - 2^32 + 1
        stosq
        mov eax, eax
        stosq
        scasq
        neg rax
        stosq
        inc byte [rdi]          ; (-1/p = 1)
        add edi, FSIZE - 32     ; n of P-256: its low half is data, then 2^64 - 1, 2^64 - 2^32
        mov esi, NLOW
        movsq
        movsq
        or rax, -1
        stosq
        shl rax, 32
        stosq
        movsq                   ; (-1/n)
        mov edi, F25519
        mov bl, 3
.f:     xor edx, edx            ; for each: 2^256 - M and M - 2
        mov cl, 4
        stc
.n:     mov rax, [rdi+F_M+rdx*8]
        mov [rdi+F_EXP+rdx*8], rax
        not rax
        adc rax, 0
        mov [rdi+rdx*8], rax
        inc edx
        loop .n
        sub byte [rdi+F_EXP], 2
        add edi, FSIZE
        dec bl
        jnz .f
        mov edi, KOFFV          ; what a nonce loses before its nibbles are looked up
        mov al, 0x11
        mov cl, 32
        rep stosb
        mov byte [rdi-1], 0x91
        inc byte [R_ONE]
        mov dword [R_A24], 121665
        ; The table for edwards25519: window i has j 16^i B for j = 0 .. 15, as
        ; (y + x, y - x, 2 d x y). One row is: the point 16^i B as such an entry in E0-E2,
        ; then 16 times: the sum so far to the table, and that point added to it.
        mov ebp, F25519
        mov edi, R_X            ; X, Y, Z = B (Z = 1), then our key's D, then C = 2 d
        mov cl, 8               ; (esi = EDC, after NLOW)
        rep movsq
        inc byte [rdi]
        mov edi, R_D
        mov cl, 8
        rep movsq
        mov edi, TABE
        mov bl, 64
.erow:  push rdi
        mov edi, R_E0
        call .epre
        pop rdi
        mov esi, X_INITED
        call .vm
        mov bh, 16
.eent:  call .epre
        mov esi, X_MADDED
        call .vm
        dec bh
        jnz .eent
        dec bl
        jnz .erow
        ; The table for P-256: window i has (j + 1) 16^i G for j = 0 .. 15, as (x, y) times R.
        ; One row is: 16 times the sum so far to the table, and 16^i G added to it (the
        ; first time that is a doubling, the last time it is left out).
        mov ebp, FP256
        mov esi, ebp            ; C = R mod p = 2^256 - p
        mov edi, R_C
        push 4                  ; (the multiplications leave nothing of rcx)
        pop rcx
        rep movsq
        mov esi, REGC           ; G
        mov edi, R_E0
        mov cl, 8
        rep movsq
        mov esi, X_INIT256
        call vm
        mov edi, TABP
        mov bl, 64
.prow:  mov bh, 16
.pent:  mov esi, X_TOAFF
        call .conv
        mov esi, R_T0
        cmp bh, 16
        jne .pcp
        push rdi
        mov edi, R_E0           ; (the first of a row is what the others add)
        push 8
        pop rcx
        rep movsq
        pop rdi
        mov esi, R_T0
.pcp:   push 8
        pop rcx
        rep movsq
        mov esi, X_DBL256
        cmp bh, 16
        je .pgo
        mov esi, X_MADD256
        cmp bh, 1
        je .pno
.pgo:   call .vm
.pno:   dec bh
        jnz .pent
        dec bl
        jnz .prow
        ret
; (the point in X.. as a table entry of edwards25519 to rdi, which moves on)
.epre:  mov esi, X_TOPRE
        call .conv
        mov esi, R_T0
        push 12
        pop rcx
        rep movsq
        ret
; (a register's address, for its number in the low four bits of eax, to edi, which moves on)
.reg:   and eax, 15
        shl eax, 5
        add eax, REGS
        stosd
        ret
; (T1 = 1 / Z, then the program at rsi; keeps rdi and rbx, as .vm does)
.conv:  push rsi
        push rdi
        push rbx
        mov esi, R_Z
        call inv
        pop rbx
        pop rdi
        pop rsi
.vm:    push rdi
        push rbx
        call vm
        pop rbx
        pop rdi
        ret

        HOT 0xE1FEE7FF
; select: entry number edx of the 16 entries (ecx bytes each, a multiple of 32) at rsi to the
; registers from E0 on. All 16 are read, and what is kept is picked with masks: which one it
; was shows neither in time nor in what the cache holds. 32 bytes of an entry at a time,
; gathered in two registers over the 16 (through memory, each of them waits for the store
; before: 355 cycles where this takes 110). rsi moves on past the 16; clobbers rax, rdx,
; rdi, r8, xmm0-xmm6.
select: mov edi, REGS
        movd xmm0, edx
        pshufd xmm0, xmm0, 0    ; the number wanted
        pcmpeqd xmm2, xmm2
        psrld xmm2, 31          ; 1
        xor eax, eax            ; where in an entry
.u:     pxor xmm1, xmm1         ; the number of the entry at hand
        pxor xmm5, xmm5
        pxor xmm6, xmm6
        lea r8, [rsi+rax]
        mov dl, 16
.e:     movdqa xmm3, xmm1
        pcmpeqd xmm3, xmm0      ; all ones for the one wanted
        movdqa xmm4, [r8]
        pand xmm4, xmm3
        por xmm5, xmm4
        pand xmm3, [r8+16]
        por xmm6, xmm3
        paddd xmm1, xmm2
        add r8, rcx
        dec dl
        jnz .e
        movdqa [rdi+rax], xmm5
        movdqa [rdi+rax+16], xmm6
        add eax, 32
        cmp eax, ecx
        jb .u
        mov eax, ecx
        shl eax, 4
        add rsi, rax
        ret

        HOT 0x0001F7CF
; fas: the four limbs at rdi = those at rsi + those at rbx if ecx = 0, minus them if ecx = 1,
; in the field at rbp: weakly reduced, as its operands are. (Clobbers rax, rcx, rdx, rsi,
; r8-r15.) If the sum left [0, 2^256) (a carry adding, a borrow subtracting), M is taken
; off, which is adding 2^256 - M, or put back; and once more if that was not enough,
; which shows in the carry of that correction (ec.py: it can take two). Both corrected
; values are made whatever the case, and one of the three is kept. For 2^255 - 19, where
; 2^256 - M is 38, the same comes shorter: the carry or borrow is 38 to add or take off,
; and what that carries or borrows is 38 once more (the number is then below 38 or within
; 38 of 2^256: only its lowest limb changes).
fas:    cmp qword [rbp+F_INV], 0
        jne .any
        test ecx, ecx
        jnz .s19
.a19:   mov r8, [rsi]           ; (`fadd19`, as the ladder's step calls it)
        mov r9, [rsi+8]
        mov r10, [rsi+16]
        mov r11, [rsi+24]
        add r8, [rbx]
        adc r9, [rbx+8]
        adc r10, [rbx+16]
        adc r11, [rbx+24]
        sbb eax, eax
        and eax, 38
        add r8, rax
        adc r9, 0
        adc r10, 0
        adc r11, 0
        sbb eax, eax
        and eax, 38
        add r8, rax
        jmp .put
.s19:   mov r8, [rsi]           ; (`fsub19`)
        mov r9, [rsi+8]
        mov r10, [rsi+16]
        mov r11, [rsi+24]
        sub r8, [rbx]
        sbb r9, [rbx+8]
        sbb r10, [rbx+16]
        sbb r11, [rbx+24]
        sbb eax, eax
        and eax, 38
        sub r8, rax
        sbb r9, 0
        sbb r10, 0
        sbb r11, 0
        sbb eax, eax
        and eax, 38
        sub r8, rax
.put:   mov [rdi], r8
        mov [rdi+8], r9
        mov [rdi+16], r10
        mov [rdi+24], r11
        ret
.any:   mov r8, [rsi]
        mov r9, [rsi+8]
        mov r10, [rsi+16]
        mov r11, [rsi+24]
        mov rdx, rbp            ; (2^256 - M, to add)
        test ecx, ecx
        jnz .sub
        add r8, [rbx]
        adc r9, [rbx+8]
        adc r10, [rbx+16]
        adc r11, [rbx+24]
        jmp .fix
.sub:   sub r8, [rbx]
        sbb r9, [rbx+8]
        sbb r10, [rbx+16]
        sbb r11, [rbx+24]
        lea rdx, [rbp+F_M]
.fix:   sbb eax, eax            ; -1: out of range
        mov r12, r8
        mov r13, r9
        mov r14, r10
        mov r15, r11
        add r12, [rdx]
        adc r13, [rdx+8]
        adc r14, [rdx+16]
        adc r15, [rdx+24]
        sbb esi, esi            ; that correction's carry: adding, it says "still too much",
        neg ecx                 ; subtracting, "enough"
        xor esi, ecx
        test eax, eax
        cmovnz r8, r12
        cmovnz r9, r13
        cmovnz r10, r14
        cmovnz r11, r15
        add r12, [rdx]
        adc r13, [rdx+8]
        adc r14, [rdx+16]
        adc r15, [rdx+24]
        and eax, esi
        cmovnz r8, r12
        cmovnz r9, r13
        cmovnz r10, r14
        cmovnz r11, r15
        jmp .put

; fmul: the four limbs at rdi = those at rsi times those at rbx in the field at rbp: mod
; 2^255 - 19, or divided by 2^256 mod M for the Montgomery fields; below 2^256 either way.
; (Clobbers rax, rcx, rdx, rsi, r8-r15.)
; ROW: %5:%4:%3:%2:%1 = %4:%3:%2:%1 + rdx * the four limbs at rsi, with two chains of
; carries at once (adcx, adox); %5 is not looked at before. (Clobbers rax, rcx.)
%macro ROW 5
        xor %5, %5
        mulx rcx, rax, [rsi]
        adcx %1, rax
        adox %2, rcx
        mulx rcx, rax, [rsi+8]
        adcx %2, rax
        adox %3, rcx
        mulx rcx, rax, [rsi+16]
        adcx %3, rax
        adox %4, rcx
        mulx rcx, rax, [rsi+24]
        adcx %4, rax
        adox %5, rcx
        adc %5, 0
%endmacro
        HOT 0xFF00000F
fmul:   mov r13, rsi
        mov rsi, rbx
        mov rdx, [r13]          ; the product, eight limbs, a row for each limb of the one
        mulx r9, r8, [rsi]      ; factor: r8 r9 r10 r11 | r12 r14 r15 r13
        mulx r10, rax, [rsi+8]
        add r9, rax
        mulx r11, rax, [rsi+16]
        adc r10, rax
        mulx r12, rax, [rsi+24]
        adc r11, rax
        adc r12, 0
        mov rdx, [r13+8]
        ROW r9, r10, r11, r12, r14
        mov rdx, [r13+16]
        ROW r10, r11, r12, r14, r15
        mov rdx, [r13+24]
        ROW r11, r12, r14, r15, r13
.red:   mov rdx, [rbp+F_INV]    ; (`fsqr` and `fmul1` come here with their eight limbs)
        test rdx, rdx
        jnz .mont
        mov dl, 38              ; 2^255 - 19: what is above 2^256 counts 38 times,
        xor eax, eax
        mulx rcx, rax, r12
        adcx r8, rax
        adox r9, rcx
        mulx rcx, rax, r14
        adcx r9, rax
        adox r10, rcx
        mulx rcx, rax, r15
        adcx r10, rax
        adox r11, rcx
        mulx rcx, rax, r13
        adcx r11, rax
        mov eax, 0
        adox rcx, rax
        adcx rcx, rax
        imul ecx, ecx, 38       ; and so does what that brought above it,
        add r8, rcx
        adc r9, rax
        adc r10, rax
        adc r11, rax
        sbb eax, eax            ; and the last carry (to a number that is small now)
        and eax, 38
        add r8, rax
        jmp .done
.mont:  push r13                ; Montgomery: four times, add the multiple of M that makes
        push r15                ; the lowest limb zero, and drop that limb (the high half
        push r14                ; comes in from the stack, a limb at a time)
        push r12
        lea rsi, [rbp+F_M]
        xor r14d, r14d          ; (the carry out of the top)
        mov r15b, 4
.r:     mov rdx, r8
        cmp qword [rbp+F_INV], 1
        je .p
        imul rdx, [rbp+F_INV]
        ROW r8, r9, r10, r11, r12
.t:     mov r8, r9
        mov r9, r10
        mov r10, r11
        pop r11
        xor eax, eax
        add r12, r14
        adc eax, eax
        add r11, r12
        adc eax, 0
        mov r14d, eax
        dec r15b
        jnz .r
        neg r14                 ; below 2^256 + M: if it left 2^256, take M off
        mov r12, [rbp]
        mov r13, [rbp+8]
        mov r15, [rbp+24]
        and r12, r14
        and r13, r14
        and r15, r14
        and r14, [rbp+16]
        add r8, r12
        adc r9, r13
        adc r10, r14
        adc r11, r15
.done:  mov [rdi], r8
        mov [rdi+8], r9
        mov [rdi+16], r10
        mov [rdi+24], r11
        ret
.p:     mov rax, r8             ; p of P-256, where -1/M is 1 and M is 2^64 - 1, 2^32 - 1, 0
        shl rax, 32             ; and a limb to multiply by: the multiple is the lowest limb's,
        mov rcx, r8             ; and with the limb it cancels it comes to that limb times
        shr rcx, 32             ; 2^32 from the second limb on and times M's last from the
        add r9, rax             ; fourth on
        adc r10, rcx
        mulx r12, rax, [rsi+24]
        adc r11, rax
        adc r12, 0
        jmp .t

        HOT 0x83FFFFFF
; fsqr: the four limbs at rdi = those at rsi, squared, in the field at rbp: what `fmul`
; makes of a number and itself (and clobbers what it does), with ten products for sixteen:
; the six of two different limbs once, doubled, and the four squares added.
fsqr:   mov rdx, [rsi]
        mulx r10, r9, [rsi+8]   ; a0 a1, a0 a2, a0 a3: r9 r10 r11 r12
        mulx r11, rax, [rsi+16]
        add r10, rax
        mulx r12, rax, [rsi+24]
        adc r11, rax
        adc r12, 0
        mov rdx, [rsi+8]
        mulx rcx, rax, [rsi+16] ; a1 a2 from r11 on, a1 a3 from r12 on (r14 above)
        add r11, rax
        adc r12, rcx
        mulx r14, rax, [rsi+24]
        adc r14, 0
        add r12, rax
        adc r14, 0
        mov rdx, [rsi+16]
        mulx r15, rax, [rsi+24] ; a2 a3 from r14 on (r15 above): below 2^448 in all,
        add r14, rax
        adc r15, 0
        xor r13d, r13d          ; twice,
        add r9, r9
        adc r10, r10
        adc r11, r11
        adc r12, r12
        adc r14, r14
        adc r15, r15
        adc r13, r13
        mov rdx, [rsi]          ; and the squares, two limbs each from r8 on
        mulx rcx, r8, rdx
        add r9, rcx
        mov rdx, [rsi+8]
        mulx rcx, rax, rdx
        adc r10, rax
        adc r11, rcx
        mov rdx, [rsi+16]
        mulx rcx, rax, rdx
        adc r12, rax
        adc r14, rcx
        mov rdx, [rsi+24]
        mulx rcx, rax, rdx
        adc r15, rax
        adc r13, rcx
        jmp fmul.red

        HOT 0xFFFF07FF
; fmul1: as `fmul`, for a number at rsi that has one limb: the first of its four rows.
fmul1:  mov rdx, [rsi]
        mulx r9, r8, [rbx]
        mulx r10, rax, [rbx+8]
        add r9, rax
        mulx r11, rax, [rbx+16]
        adc r10, rax
        mulx r12, rax, [rbx+24]
        adc r11, rax
        adc r12, 0
        xor r14d, r14d
        xor r15d, r15d
        xor r13d, r13d
        jmp fmul.red

        HOT 0x60000790
; inv: T1 = (the four limbs at rsi) ^ (m - 2) in the field at rbp: the inverse, or for a
; Montgomery field R^2 / it of a raw number, 1 / it of a stored one. Clobbers T0 (and for
; 2^255 - 19 T2 and T3) and all registers but rbp. (The exponent is no secret.) Mod 2^255
; - 19 by the addition chain of tools/ec.py, the others bit by bit.
inv:    mov edi, R_T0
        push 4
        pop rcx
        rep movsq               ; T0 = x
        cmp ebp, F25519
        je .chain
        lea rsi, [rdi-32]
        mov cl, 4
        rep movsq               ; T1 = x (bit 0 of m - 2 is set)
        inc ecx                 ; bit 1
.l:     push rcx
        mov edi, R_T0
        mov esi, edi
        mov ebx, edi
        call fsqr               ; T0 = T0^2
        pop rcx
        bt [rbp+F_EXP], ecx
        jnc .s
        push rcx
        mov edi, R_T1
        mov esi, edi
        call fmul               ; T1 = T1 * T0
        pop rcx
.s:     inc cl
        jnz .l
.ret:   ret
.chain: mov esi, X_INV25519     ; (unpacked as `vm` has programs: dst, a, b, and for the op
.op:    mov edi, [rsi]          ; its count of squarings in NSQ)
        test edi, edi
        jz .ret
        mov ebx, [rsi+8]
        mov ecx, [rsi+12]
        movzx ecx, byte [rcx+NSQ]
        push rsi
        mov esi, [rsi+4]
        jrcxz .m
.sq:    push rcx
        call fsqr               ; dst = a^2, then dst = dst^2 so often,
        pop rcx
        mov esi, edi
        loop .sq
.m:     call fmul               ; then dst = that * b
        pop rsi
        add esi, 16
        jmp .op

; ecinit (boot): the three fields, the constant registers and the two tables.
; A field is: 2^256 - M | M | -1/M mod 2^64 (0 for 2^255 - 19, which is reduced its own
; way and has M = 2^256 - 38, twice the prime) | m - 2, the exponent that inverts.
%ifdef HOST
bdrain: ret                     ; (the tests have no device)
echost: pushad                  ; (for the tests: C wants its registers back)
        call ecinit
        popad
        ret
; (for test/bench.c: one operation, or one program, in the field number ecx)
        global select, cswap, hstep, hfmul, hfsqr, hfmul1, hfas, hfsub, hvm, hinv, F25519, HK, HKSET, POOLN, hstock, HAAD, HAADN, hctr_test_seed, hctr_test_generate
HK      equ BSS + 0x18000       ; (nonces for the signatures after the next `stock`: see there)
HKSET   equ HK + NPOOL * 32
HAAD    equ HKSET + 16          ; (16 bytes to make a tag over in place of a record's header,
HAADN   equ HAAD + 16           ; if HAADN is not 0: then so many of them count, less 1)
; haad (`seal`, before it makes the tag of the ebp blocks at rsi; rax = where the lengths
; are): Wycheproof's vectors for AES-128-GCM have data of their own where a record has
; its header, or none: then the header's block is not part of what is hashed.
haad:   movzx edx, byte [HAADN]
        dec edx
        js .no
        jnz .some
        add esi, 16
        dec ebp
.some:  movdqu xmm5, [HAAD]
        movdqa [SB], xmm5
        shl edx, 3
        mov [rax+7], dl
.no:    ret
hstock: pushad
        call stock
        popad
        ret
hctr_test_seed:
        mov qword [DRBGK], 0
        mov qword [DRBGK+8], 0
        mov qword [DRBGV], 0
        mov qword [DRBGV+8], 0
        mov dword [DRBGN], 0
        mov dword [DRBGR], 1
        mov rsi, rdi
        call hctr_update
        ret
hctr_test_generate:
        call hctr_generate
        ret
hfield: imul ebp, ecx, FSIZE
        add ebp, F25519
        ret
hfmul:  pushad
        call hfield
        call fmul
        popad
        ret
hstep:  pushad                  ; (the ladder's step alone, for test/bench.c)
        mov ebp, F25519
%include "step.inc"
        popad
        ret
hfsqr:  pushad
        call hfield
        call fsqr
        popad
        ret
hfmul1: pushad
        call hfield
        call fmul1
        popad
        ret
hfas:   pushad
        call hfield
        xor ecx, ecx
        call fas
        popad
        ret
hfsub:  pushad
        call hfield
        push 1
        pop rcx
        call fas
        popad
        ret
hvm:    pushad
        call hfield
        call vm
        popad
        ret
hinv:   pushad
        call hfield
        call inv
        popad
        ret
%endif
