; timer.asm: the connections that are owed something, and the clock. A part of os.asm, which includes it.
; tarm: connection rbp is owed something: an ack is outstanding, or it has more to get than
; its client takes for now. It joins this processor's queue of such connections, as the
; first 64 bytes of the frame in hand (which say who the client is and how to reach it)
; with, in place of what is of no use in them, the time, the client's ack as it is, and how
; often in a row it has been sent to in vain (TQTRY). `tqrun` looks at them when the
; processor has nothing else to do. A connection is in the queue once (F_ARMED); if the
; queue is full, it does not join, and its next packet tries again.
tarm:   pushad
        mov eax, [TQT]
        mov edx, eax
        sub edx, [TQH]
        cmp edx, [TMMASK]
        ja .full
        call tqslot
        xor esi, esi            ; FR
        push 8
        pop rcx
        rep movsq
        mov edx, [TNOW]
        mov [rax+T_TIME], edx
        mov edx, [rbp+C_ACK]
        mov [rax+T_ACK], edx
        mov dl, [TQTRY]
        mov [rax+T_TRY], dl
        mov dl, [rbp+C_RTO]
        mov [rax+T_RTO], dl
        inc dword [TQT]
        or byte [rbp+C_FL2], F_ARMED
.full:  popad
        ret
tqslot: and eax, [TMMASK]
        shl eax, 6
        add eax, [TQB]
        mov edi, eax
        ret

; tqrun: the connection that has been in that queue the longest (if there is one). If it
; has not waited as long as its round trip says yet (C_RTO: a quarter of a second for a
; client nearby; twice as long for each time it has been sent to in vain, up to 16 s),
; it goes to the back. If it has: its frame
; is put where a frame from its client would be, and if the client then has everything,
; that is that; if its ack has moved since, it joins the queue afresh; if not, what it
; asks for is sent again, as for a client that asks (E_RTO in `tcp.tx`). Only when there
; is nothing else to do: while frames wait in our ring, the client's ack may be one of
; them. And not for ever: after six times in vain, a client from which nothing at all has
; come for a minute or two (C_AGE) is told that its connection is no more, and it is no
; more. (Or every client that vanished in the middle of a response would be sent to every
; 16 s for as long as we are up, and keep one of the queue's 4 n places: with all of them
; taken, nobody's timer runs.) (Clobbers everything.)
tqrun:  mov eax, [TQH]
        cmp eax, [TQT]
        je .none
        inc dword [TQH]
        call tqslot
        xchg eax, esi
        mov edx, [TNOW]         ; (`tidle` has just read the clock)
        sub edx, [rsi+T_TIME]
        movzx eax, byte [rsi+T_RTO]
        shl eax, 5              ; (how long the first time, in ticks)
        mov cl, [rsi+T_TRY]
        shl eax, cl
        push 8
        pop rcx
        cmp edx, 1 << 15        ; (16 s is the longest wait there is)
        jae .due
        cmp edx, eax
        jae .due
        mov eax, [TQT]
        inc dword [TQT]
        call tqslot
        rep movsq
.none:  ret
.due:   xor edi, edi            ; FR
        rep movsq
        xor ebx, ebx
        mov [rbx+P_ADV], ebx
        mov [rbx+P_WIN], bx     ; (what the client took when that frame came, it need not
                                ; take now: on the timer's word nothing new goes)
        mov word [rbx+P_MORE], E_RTO << 8
        call find
        jc .none                ; (the connection is no more,
%ifdef RACE
%if RACE = 1
        RACEWAIT [rbp+C_AGE]
%endif
%endif
        call hold               ; or its slot another's by now.) In use from here on, as
        jne .none               ; for a packet of its client's. But this is none: when the
        push rax                ; client was last heard is kept, and put back at the end
%ifdef RACE
%if RACE = 2
        RACEWAIT [rsp]
%endif
%endif
        and byte [rbp+C_FL2], ~F_ARMED
        call sm
        jnc .back               ; (another connection of that client's)
        call geom
        mov eax, [TXEND]
        test byte [rbp+C_FL2], F_FIN
        jz .nf
        inc eax
.nf:    mov edx, [rbp+C_ACK]
        cmp eax, edx
        je .back                ; (it has everything)
        mov cl, [rbx+T_TRY]
        cmp edx, [rbx+T_ACK]
        je .vain
        mov [rbx+P_EV], bl      ; (it is getting on: nothing is sent again)
        mov cl, -1
.vain:  inc ecx
        cmp cl, 6
        jbe .t
        mov cl, 6               ; (16 s at a time from here on.) And a client that has said
        mov al, [NOW]           ; nothing at all for a minute or two while we sent to it in
        sub al, [rsp]           ; vain has gone: that was the connection. (One that takes
        cmp al, 2               ; no more for now, and says so each time it is sent to,
        jb .t                   ; stays.)
        pop rax
        jmp tcp.reset
.t:     mov [TQTRY], cl
        call tcp.tx
        mov byte [TQTRY], 0
.back:  pop rax                 ; The slot, if it still is this connection's (that may have
        call own                ; been its end), says again when its client was last heard:
        jne .kept               ; a slot the timer alone keeps busy is a quiet one, to be
        mov [rbp+C_AGE], al     ; taken when there is no room
.kept:  ret
; The one thing we send unasked: a SYN-ACK again. We keep no connection for a SYN, so a
; lost SYN-ACK costs the client a second, and after that a retransmission timeout of
; seconds for the rest of the connection (it has sent its SYN twice, so it has no round
; trip to go by). Instead the SYNs of late are kept: 4 n places (see TABV), a client's
; picked by its hash, whatever was there is gone. A connection made takes its SYN out
; (`.make`). A polling loop with no frame to handle goes round the places, 8 a turn
; (`tidle`), and a SYN that is still there after a quarter of a second
; goes through `tcp` once more, as if it had just come, three times at most.
; Only then: while frames wait in our ring, the client's answer may be one of them (under
; more load than we can take, they wait longer than that). No more than one such a tick
; (1/2048 s): a flood of SYNs from made-up addresses gets one SYN-ACK each as before,
; and at most two thousand a second on top.
; tnote: keep the SYN in FR, if it is no longer than 120 bytes (they are 74)
tnote:  pushad
        mov ecx, [RXLEN]
        cmp ecx, 120
        ja .no
        movzx eax, byte [TTRY]
        test eax, eax
        jnz .ours
        mov al, 4               ; (the client's own: it may be answered three times more)
.ours:  dec eax
        jz .no
        mov edx, [HKO+12]
        and edx, [TMMASK]
        mov edi, [TMT]
        mov esi, [TNOW]
        or esi, 1
        mov [rdi+rdx*4], esi
        shl edx, 7
        add edx, [TMF]
        mov [rdx], al
        mov [rdx+1], cl
        lea edi, [rdx+8]
        xor esi, esi            ; (FR)
        push 15
        pop rcx
        rep movsq
        mov eax, [rdx+8+P_SEQ]  ; (as it came: `tcp` has turned these two round)
        bswap eax
        mov [rdx+8+P_SEQ], eax
        mov eax, [rdx+8+P_ACK]
        bswap eax
        mov [rdx+8+P_ACK], eax
.no:    popad
        ret

; tidle: the next 8 places of this processor's: a SYN that has waited long enough? Then it
; is answered again (one at most). (Clobbers everything.)
tidle:  call clock
        xchg eax, edx
        push 8
        pop rsi
.next:  mov eax, [abs NCPUM]
        inc eax
        imul eax, [THAND]
        inc dword [THAND]
        add eax, [CPUN]
        and eax, [TMMASK]
        mov edi, [TMT]
        lea rdi, [rdi+rax*4]
        mov ecx, edx
        sub ecx, [rdi]          ; how long it has been there, if anything is (signed: one
        cmp ecx, 512            ; noted this very tick may be a tick ahead)
        jl .young
        cmp dword [rdi], 0
        jne .due
.young: dec esi
        jnz .next
        ret
.due:   cmp edx, [TLAST]
        je .no
        mov [TLAST], edx
        and dword [rdi], 0
        count 4
        shl eax, 7
        add eax, [TMF]
        mov cl, [rax]
        mov [TTRY], cl
        movzx ecx, byte [rax+1]
        mov [RXLEN], ecx
        lea esi, [rax+8]
        xor edi, edi
        push 15
        pop rcx
        rep movsq
        xor ebx, ebx
        movzx ecx, byte [rbx+46]
        shr ecx, 4
        shl ecx, 2              ; (as `tcp` has it where the checksum has been found right:
        call tcp.sums           ; a SYN is its header)
        mov byte [TTRY], 0
.no:    ret

; tsc: rax = 64-bit cycle counter (clobbers rdx)
tsc:    rdtsc
        shl rdx, 32
        or rax, rdx
        ret

; clock: eax (and TNOW) = the time in ticks of 1/2048 s; NOW = in units of 64 s (clobbers rdx)
clock:  call tsc
        mul qword [TSCM]
        mov [TNOW], edx
        mov eax, edx
        shr rdx, 17
        mov [NOW], dl
        ret
