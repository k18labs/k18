; send.asm: the segments of the response a connection is in the middle of. A part of os.asm, which includes it.
; sm: CF if connection rbp is a TLS one whose client has had our flight: what it gets from
; then on is cut from the response in hand (`tcp.tx`). (ebx = 0)
sm:     cmp [rbx+P_PORTS+2], bl
        je .no
        cmp dword [rbp+C_ST], 0
        je .no
        push rax
        mov eax, [rbp+C_ACK]
        sub eax, [rbp+C_RS]
        not eax
        add eax, eax
        pop rax
.no:    ret

; ackno: edi = what we acknowledge to the client of connection rbp
ackno:  mov edi, [rbp+C_NXT]
        test byte [rbp+C_FLG], F_DEFER
        jz .all
        dec edi
.all:   ret

; geom: the response connection rbp has in hand, and how it is cut: a segment has TXM bytes
; (the client's choice, see MSSTAB), and holds one record, of which TXP bytes are the
; response's. The response is the TXL bytes at TXBLOB (or only their head), goes in TXN
; records, and its last byte has the sequence number before TXEND. Keeps all registers.
geom:   pushad
        movzx eax, byte [rbp+C_FLG]
        shr eax, 2
        and eax, 3
        movzx ecx, word [MSSTAB+rax*2]
        mov [TXM], ecx
        sub ecx, 22             ; (a record's header, the byte that says what it holds, its tag)
        mov [TXP], ecx
        movzx eax, word [rbp+C_AS]
        mov esi, eax
        shl esi, 17             ; (its low 15 bits, times 16)
        shr esi, 13
        add esi, SITE + AT_OFF  ; where it is, its length, its head's length
        mov edx, [rsi]
        add edx, SITE
        mov [TXBLOB], edx
        add ax, ax              ; (only the head?)
        mov eax, [rsi+4]
        jnc .all
        mov eax, [rsi+8]
.all:   mov [TXL], eax
        lea eax, [rax+rcx-1]
        xor edx, edx
        div ecx
        mov [TXN], eax
        imul eax, eax, 22
        add eax, [TXL]
        add eax, [rbp+C_RS]
        mov [TXEND], eax
        popad
        ret

; sendseg: the segment of the response in hand (`geom`) that begins with sequence number
; eax goes out: the record that byte is in, from that byte on; behind the response's last
; byte, our FIN, if the connection is closed. C_SND moves on if this is further than we
; had sent. Keeps all registers. (ebx = 0)
sendseg:
        pushad
.in:    mov edi, eax
        sub eax, [rbp+C_RS]     ; how far into the response's bytes on the wire that is
        mov ecx, [TXEND]
        mov edx, ecx
        sub ecx, [rbp+C_RS]
        cmp eax, ecx
        jb .data
        mov edi, edx            ; behind them: nothing but our FIN can go
        xor ecx, ecx
        push 1
        pop rsi                 ; (and nothing of a frame of our own: see `.seg`)
        mov al, 0x10
        test byte [rbp+C_FLG], F_CLOSED
        jnz .close
        popad
        ret
.data:  xor edx, edx
        div dword [TXM]         ; eax = which record, edx = how far into it
        push rdx
        push rdi
        mov esi, eax
        imul esi, [TXP]         ; the response's bytes before that record,
        mov ecx, [TXL]
        sub ecx, esi            ; and from it on: a record's worth of them
        cmp ecx, [TXP]
        jbe .n
        mov ecx, [TXP]
.n:     add esi, [TXBLOB]
        add eax, [rbp+C_SR]
        xchg eax, edx           ; the record's number
        lea rbx, [rbp+C_KIV]
        mov edi, OB
        mov al, 23              ; (what it holds: application data)
        clc
        call seal
        pop rdx                 ; the sequence number
        pop rsi
        mov ecx, edi
        sub ecx, OB
        sub ecx, esi            ; so many bytes go,
        add esi, OB
.fl:    lea edi, [rdx+rcx]      ; and up to here
        mov al, 0x10
        cmp edi, [TXEND]
        jne .go
        mov al, 0x18            ; (the last of it: push)
        test byte [rbp+C_FLG], F_CLOSED
        jz .go
.close: or al, 1                ; our FIN, which takes a number too
        or byte [rbp+C_FL2], F_FIN
        inc edi
.go:    push rdi                ; C_SND moves on if this is further. (Sequence numbers go
        sub edi, [rbp+C_SND]    ; round: which of two is further says the sign of their
        dec edi                 ; difference, not a comparison: a `jle` here would stop a
        pop rdi                 ; response for ever where it crosses 2^31.)
        js .seg
        mov [rbp+C_SND], edi
.seg:   call ackno
        test esi, esi
        jnz .one
        call tcp_big            ; (many records in a frame of our own, from `sendrun`: the
        call txkick             ; device is told at once, there is a round trip's worth in it)
        jmp .sent
.one:   call tcp_seg
.sent:  popad
        or byte [rbx+P_EV], E_SENT
        ret

; sendrun: more of the response in hand goes out, from eax = C_SND on: `tcp.tx` has seen
; that the client takes the next record. If the card cuts frames into segments for us
; (TSO): all the records that end before TXLIM, which is as far as the client takes it
; for now, up to as many as a frame of 64 KiB holds, in one frame. A record is a segment,
; so the card cuts where we would have, and what is lost on the way is one record, made
; again as ever (`sendseg`). If it does not, or there is only one record to go (the
; response's last may be a short one, which no multiple of a segment counts in):
; `sendseg`. Keeps all registers. (ebx = 0)
sendrun:
%ifdef OURIP6
        call cuts
%else
        cmp byte [TSO], 0
%endif
        je sendseg
        pushad
        mov ecx, [TXM]
        mov esi, eax            ; From here on:
        mov eax, [TXLIM]
        sub eax, esi            ; what the client takes for now,
        mov edx, BIGPAY
        cmp eax, edx
        cmova eax, edx          ; or what a frame holds,
        xor edx, edx
        div ecx
        imul eax, ecx           ; in whole records (none that reaches further),
        mov edx, [TXEND]
        sub edx, esi
        cmp eax, edx
        cmova eax, edx          ; or what is left of the response
        cmp eax, ecx
        ja .many
        xchg eax, esi           ; (one record: as ever, and what it saved is what we
        jmp sendseg.in          ; saved)
.many:  push rax                ; (so many bytes)
        call txbig              ; ebx = a frame of this processor's own
        mov eax, [rbp+C_SND]
        sub eax, [rbp+C_RS]
        xor edx, edx
        div ecx                 ; The first of them is this record of the response (we
        mov esi, eax            ; send whole records: C_SND is where one begins),
        imul esi, [TXP]
        add esi, [TXBLOB]       ; its bytes are here,
        add eax, [rbp+C_SR]
        xchg eax, edx           ; and this is its number
        lea edi, [rbx+54]
        pop rcx
        push rbx
        add ecx, edi
        push rcx                ; (where the frame will end)
        lea rbx, [rbp+C_KIV]
.rec:   mov ecx, [rsp]
        sub ecx, edi            ; What is left to fill: a record of it,
        mov eax, [TXM]
        cmp ecx, eax
        cmova ecx, eax
        sub ecx, 22             ; of which so many bytes are the response's
        mov al, 23
        clc
        call seal               ; (edi moves on)
        add esi, ecx
        inc edx
        call bdrain             ; (a frame of records takes its time: what comes in meanwhile
        cmp edi, [rsp]          ; goes on to the rings)
        jb .rec
        pop rcx
        pop rbx                 ; The frame,
        sub ecx, ebx
        sub ecx, 54             ; how many bytes lie in it,
        mov edx, [rbp+C_SND]    ; and their sequence number
        xor esi, esi            ; (nothing is to be copied)
        jmp sendseg.fl
