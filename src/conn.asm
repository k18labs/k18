; conn.asm: the tables of connections, the keyed hash that places them, and the SYN cookie.
; A part of os.asm, which includes it.
; find: ebp = the slot of the connection the packet in FR belongs to. If it has none: CF, and
; ebp = the slot a new one would get, or 0 if there is no room for it.
; A connection is in one of two buckets of BUCKET slots, picked by two words of the keyed
; hash of its address and ports (`prf`; clients can't aim at each other's buckets). A new one
; goes into the bucket with more free slots. If both are full, it takes the place of the
; connection in them that has been quiet for the longest, if that is longer than IDLE (about
; an hour): such a client has probably gone without saying so. If none has, the new one is
; refused.
; The processors take slots from each other, and a slot changes hands in one step: its
; first eight bytes (address, port, flags, C_AGE) become the new connection's if they still
; are as they were seen here (`tcp.make`). The processor whose connection it was says "in
; use" in one step as well, by changing C_AGE, before it does anything else with that
; connection, and then looks whether the slot still is that connection's (`hold`, which
; `tcp` and `tqrun` call after us). So one of the two finds out: the new connection that
; the slot is not as it was, or the old one that it has none.
find:   pushad
        xor esi, esi
%ifdef OURIP6                   ; (A frame that came over IPv6, as `tcp6` left it: the hash
        cmp word [rsi+12], 0xDD86 ; is of the client's 16 bytes and its ports, and what
        jne .v4                 ; stands for the client in a slot's four bytes of address
        movq xmm0, [rsi+14]     ; is 32 bits of that hash, never 0: nobody can pick an
        pinsrd xmm0, [rsi+22], 2 ; address that looks like another's there, as nobody has
        pinsrd xmm0, [rsi+30], 3 ; the key.)
        mov edi, [rsi+34]
        call prf6.go
        movdqa [HKO], xmm0
        pextrd eax, xmm0, 3
        or al, 1
        mov [abs P_IP], eax
        jmp .again
.v4:
%endif
        call prf
        movdqa [HKO], xmm0
.again: mov esi, PT             ; the table for port 80,
        push PSLOT
        pop rcx
        cmp byte [abs P_PORTS+2], 0
        je .tab
        mov esi, TT             ; or the one for TLS
        mov cl, TSLOT
.tab:   mov eax, [HKO+4]
        call .where
        push rbp                ; the second bucket
        mov eax, [HKO]
        call .where
        push rbp                ; the first
        xor esi, esi            ; (FR; and) esi = the slot that has been quiet for longer than bh
        mov eax, [rsi+P_IP]
        mov di, [rsi+P_PORTS]
        mov bh, IDLE
        call .scan
        mov bl, dl              ; free slots in the first bucket
        mov rbp, [rsp+8]
        call .scan
        pop rax
        pop rbp
        cmp dl, bl
        ja .pick                ; the second has more
        xchg rax, rbp
        mov dl, bl
.pick:  test dl, dl
        jnz .free
        mov rbp, rsi            ; no free slot in either
        jmp .miss
.free:
%ifdef RACE
%if RACE = 3                    ; (make RACE=3, for tools/racetest.py 3: the one free slot that
        test byte [abs P_FL], 2 ; was counted is another's by the time we get to it, as when
        jnz .walk               ; another processor has made a connection there meanwhile:
        cmp dl, 1               ; here a made-up one, and not for a SYN, which takes no slot)
        jne .walk
        push rbp
.gone:  cmp dword [rbp+C_IP], 0
        je .took
        add rbp, rcx
        jmp .gone
.took:  mov dword [rbp+C_IP], 0x0100007F
        pop rbp
.walk:
%endif
%endif
        mov dh, BUCKET          ; The first free slot of that bucket. If there is none any
.f:     mov rax, [rbp]          ; more (another processor has taken what was free when it
        test eax, eax           ; was counted), all of it again: the walk must not go on
        jz .mine                ; into the next bucket, or out of the table
        add rbp, rcx
        dec dh
        jnz .f
        jmp .again
.mine:  mov [CLAIMQ], rax       ; (what is there now: see `.make` in `tcp`)
.miss:  stc
.ret:   mov [rsp+16], rbp
        popad
        ret
.where: mul dword [rsi+8]       ; rbp = the bucket for hash eax: number (hash * buckets) >> 32
        imul rdx, rcx
        shl rdx, 4              ; (* BUCKET)
        add rdx, [rsi]
        mov rbp, rdx
        ret
.scan:  mov edx, BUCKET << 8    ; dh = slots to look at, dl = free ones seen
.s:     cmp [rbp+C_IP], eax
        jne .other
        cmp [rbp+C_PORT], di
        jne .other
        add rsp, 24             ; found (CF = 0): drop the return address and the buckets
        jmp .ret
.other: cmp dword [rbp+C_IP], 0
        jne .used
        inc edx
        jmp .nx
.used:  push rax
        mov rax, [rbp]          ; One look at it: what a new connection then asks for (`.make`
        push rax                ; in `tcp`) is the slot as it was found quiet, to the bit.
        shr rax, 56             ; (its C_AGE)
        sub al, [NOW]
        neg al                  ; How long it has been quiet: longer than the longest so far?
        cmp al, bh              ; (But not all of 255 units: the next packet of its own, a
        jbe .not                ; unit on, would leave C_AGE as it is, and it is by changing
        cmp al, 255             ; C_AGE that its processor says "in use": see `tcp`.)
        je .not
        mov bh, al
        mov rsi, rbp
        pop qword [CLAIMQ]
        jmp short .young
.not:   pop rax
.young: pop rax
.nx:    add rbp, rcx
        dec dh
        jnz .s
        ret

; hold: the slot at rbp, which `find` says is the connection's whose packet is in FR, is in
; use from here on: its C_AGE says now, and al = what it said (when the client was last
; heard). ZF unless the slot is another connection's by now.
; This is the owner's half of how a slot changes hands between processors (`find` has the
; taker's): before anything is done with a connection, for a packet of its client's or
; because its timer has run (`tqrun`), its processor says "in use", in one step (xchg), by
; changing one of the eight bytes a taker asks for. They are then not as a taker saw them,
; and it gets nothing; and whoever looks from now on sees a slot that is not quiet. Then,
; in one look, whether the slot still is this connection's: if a taker was quicker, there
; is no connection, and the packet is as good as lost.
; own: only that look. (ebx = 0; both clobber rdi.)
hold:   mov al, [NOW]
        xchg [rbp+C_AGE], al
own:    mov rdi, [rbp]
        cmp edi, [rbx+P_IP]
        jne .no
        shr rdi, 32
        cmp di, [rbx+P_PORTS]
.no:    ret

; prf: xmm0 = a keyed hash of the client's address and ports (and ours: twelve bytes of the
; frame at rsi; `find` keeps it in HKO): eleven rounds of AES, as the processor has them, with round keys that are simply
; random, made at boot (HKS). Its four words pick the two buckets (0, 1), make the cookie
; (2: W) and place a segment kept for later (3). (Clobbers esi and ecx; and for a frame
; of IPv6, eax and edi: `prf6`.)
prf:
%ifdef OURIP6
        cmp word [rsi+12], 0xDD86
        je prf6
%endif
        movdqu xmm0, [rsi+P_IP-FR]  ; the addresses and ports, and four bytes behind them
        pslldq xmm0, 4          ; that go again
.go:    mov esi, HKS
        pxor xmm0, [rsi]
        push 10
        pop rcx
.r:     add esi, 16
        aesenc xmm0, [rsi]
        loop .r
        ret
%ifdef OURIP6
; prf6: the same for a frame of IPv6 as it came (`drain`): of its sender's address, and,
; through the cipher a second time, of its ports (so that what one address and port is
; told, the cookie, is of no use to another). `.go`: of the address xmm0 and the ports
; edi (`find`, which has the frame as `tcp6` left it). (Clobbers eax, ecx, esi, edi.)
prf6:   movdqu xmm0, [rsi+22]
        mov edi, [rsi+54]
.go:    call prf.go
        pextrd eax, xmm0, 0
        xor eax, edi
        pinsrd xmm0, eax, 0
        jmp prf.go
%endif

; ckx: eax = 0 (and ZF) if the packet is the first after a SYN-ACK of ours: its ack is the
; cookie for its sequence number (see `.syn`). Bits HINT of eax are 0 if it acknowledges a
; SYN-ACK of ours at all.
ckx:    push rdx                ; (ebx = 0)
        mov eax, [rbx+P_SEQ]
        dec eax
        shl eax, 14
        xor eax, [HKO+8]
%ifdef ISNTOP                   ; (test builds: as `.syn` made it)
        and eax, ISNLOW
        or eax, ISNTOP & ~ISNLOW
%endif
        mov edx, [rbx+P_ACK]
        dec edx
        xor eax, edx
        and eax, -64            ; (the low six bits are what the SYN-ACK noted, not W)
        pop rdx
        ret
