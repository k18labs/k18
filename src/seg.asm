; seg.asm: port 80's answer, segments that came early, handshake buffers, and segments of
; our own making. A part of os.asm, which includes it.
; respond: what port 80 says to every request (tools/pack.py: the page at /, or where to go
; instead), at edi, which moves on. (ebx = 0)
respond:
        push rsi
        push rcx
        mov esi, SITE + P80_OFF
        mov ecx, P80_LEN
        rep movsb
%ifdef DEBUG
        pushad
        mov al, [abs NCPUM]     ; (the first two digits: how many processors take frames,
        shl al, 4               ; less 1, and which one this is)
        or al, [CPUN]
        mov [DBG+1], al
        mov eax, [DBG+24]       ; (counter 1: cycles per frame)
        mov edx, [DBG+28]
        div dword [DBG+32]
        mov [DBG+4], eax
%if DEBUG == 2                  ; (make DEBUG=2: how busy, in place of counters 3 and 5)
        mov eax, [DBG+36]
        shr eax, 12
        mov [DBG+12], eax
        rdtsc
        shrd eax, edx, 24
        mov [DBG+20], eax
%elif DEBUG == 3                ; (make DEBUG=3: what was asked of DHCP, and its yeses)
        mov eax, [DBG+40]
        mov [DBG+12], eax
        mov eax, [DBG+44]
        mov [DBG+20], eax
%endif
        dec edi                 ; (the page ends with a line end)
        mov esi, DBG + 24
        std
.dc:    sub esi, 4
        mov edx, [rsi]
        mov cl, 4
.dd:    mov al, dl
        and al, 15
        cmp al, 10              ; hex digit
        jb .dg
        add al, 7
.dg:    add al, '0'
        dec edi
        mov [rdi], al
        shr edx, 4
        loop .dd
        cmp esi, DBG
        ja .dc
        cld
        popad
%endif
        pop rcx
        pop rsi
        ret

; oohold: keep the segment in hand (ecx bytes at esi, sequence number P_SEQ, FIN or not)
; until what comes before it is here (`.reply` in `tcp`). There are n places (TABV) for such
; segments; a client's place is picked by its hash, and whatever was there is gone, unless
; it is an earlier segment of the same client.
oohold: pushad                  ; (ebx = 0)
        call ooent
        mov eax, [rbx+P_SEQ]
        jne .fill
        cmp eax, [rdx+OO_SEQ]
        jns .ret                ; the one kept comes first
.fill:  mov [rdx+OO_SEQ], eax
        mov eax, [HKO+12]
        mov [rdx+OO_TAG], eax
        mov [rdx+OO_LEN], ecx
        mov al, [rbx+P_FL]
        and al, 1
        mov [rdx+OO_FIN], al
        lea edi, [rdx+OO_DATA]
        rep movsb
.ret:   popad
        ret

; ooent: edx = the client's place for a segment kept for later; ZF if what is there is its own
ooent:  push rax
        mov eax, [HKO+12]
        mov edx, eax
        and edx, [HSMASK]
        shl edx, 11
        add edx, [OOBASE]
        cmp [rdx+OO_TAG], eax
        pop rax
        ret

; hsbuf: ebx = the handshake buffer of connection ebp; CF if it has none (any more)
hsbuf:  movzx ebx, word [rbp+C_HS]
        dec ebx
        js .none
        shl ebx, HS_SHIFT
        add ebx, HSP
        cmp [rbx+HS_OWNER], rbp
        je .ok
.none:  stc
.ok:    ret

; hsnew: ebx = a handshake buffer for connection rbp: the next in a circle that is not in
; use, which is to say: whose owner's slot no longer names it (the slot lets go of it when
; the client has the flight, and so does a slot that is given to another connection). If
; 16 in a row are in use, the 16th is taken all the same: its owner's ClientHello, if that
; was arriving in pieces, is then never finished, and its flight can't be sent a second time.
; (Clobbers rdx.)
hsnew:  push rax
        push rcx
        push 16
        pop rcx
.t:     mov eax, [abs NCPUM]    ; (every processor has its own: one in so many)
        inc eax
        imul eax, [HSNEXT]
        inc dword [HSNEXT]
        add eax, [CPUN]
        and eax, [HSMASK]
        mov ebx, eax
        shl ebx, HS_SHIFT
        add ebx, HSP
        inc eax                 ; (what C_HS calls it)
        mov rdx, [rbx+HS_OWNER]
        test rdx, rdx
        jz .take
        cmp [rdx+C_HS], ax
        jne .take
        cmp dword [rdx+C_IP], 0
        loopne .t
.take:  mov [rbx+HS_OWNER], rbp
        and dword [rbx+HS_FLEN], 0
        mov [rbp+C_HS], ax
        pop rcx
        pop rax
        ret

; tcp_send: ecx bytes at esi to the client of connection ebp, in segments, from our sequence
; number edx; flags al on the last. If it takes several segments, none of them acknowledges
; the last byte the client sent: the client then keeps sending that byte until it has all
; of the answer, whichever part gets lost, and it is acknowledged when its ack says so
; (F_DEFER, in `tcp`). Not when we close: then there is no later.
; (The last byte the client sent, not what this packet brought: an answer that goes out
; again because of a duplicate ack is sent for a packet that brought nothing, and its
; segments would acknowledge everything; if the one that fills the hole is lost again, and
; the client's next duplicate ack too, nobody has anything left to send.)
tcp_send:
        pushad
        movzx ebx, byte [rbp+C_FLG]
        shr ebx, 2
        and ebx, 3
        movzx ebx, word [MSSTAB+rbx*2]
        call ackno
        test al, 1
        jnz .fin
        jrcxz .last
.fin:   mov edi, [rbp+C_NXT]
        and byte [rbp+C_FLG], ~F_DEFER
        cmp ecx, ebx
        jbe .last
        test al, 1
        jnz .seg
        dec edi
        or byte [rbp+C_FLG], F_DEFER
.seg:   push rax
        push rcx
        mov ecx, ebx
        mov al, 0x10
        call tcp_seg
        pop rcx
        pop rax
        add esi, ebx
        add edx, ebx
        sub ecx, ebx
        cmp ecx, ebx
        ja .seg
.last:  call tcp_seg
        popad
        ret

; tcp_seg: send one segment to the sender of the frame in FR: ecx bytes at esi, flags al,
; sequence number edx, ack edi.
; tcp_big: the same for ecx bytes that lie in a frame of the caller's own already (`txbig`:
; at ebx, behind the place of the headers), and are more than a segment: the card cuts them
; into segments of TXM bytes, gives each these headers (the flags to the last), and sums
; each. (r8: the caller's frame, or 0.)
tcp_big: mov r8d, ebx
        jmp tcp_seg.in
tcp_seg: xor r8d, r8d
.in:    pushad
        mov ebp, ecx            ; payload length
        call txbuf              ; ebx = a frame for it; and the ring is ours until `txgo`
        test r8d, r8d
        cmovnz ebx, r8d
%ifdef OURIP6                   ; (Over IPv6, which has 20 bytes more of header, a frame of
        jnz .at                 ; ours begins 20 bytes before where a caller's would: from
        cmp word [abs 12], 0xDD86 ; ebx on, TCP's header and what it carries lie as ever.)
        jne .at
        add ebx, 20
.at:
%endif
        bswap edx
        mov [rbx+38], edx
        bswap edi
        mov [rbx+42], edi
        mov dl, 0x50
        test al, 2
        jz .nopt
        lea edx, [rdx+rcx*4]    ; (a SYN's "payload" is its options: so much longer its header)
.nopt:  mov [rbx+46], dl
        mov [rbx+47], al
        xor eax, eax
        mov [rbx+50], eax       ; checksum (for now), nothing urgent
        dec eax
        mov [rbx+48], ax        ; window: we take whatever comes, at once
        test r8d, r8d
        jnz .hdr
        lea edi, [rbx+54]
        rep movsb
        mov [rdi], cl           ; zero pad byte for an odd length checksum
.hdr:
%ifdef OURIP6
        cmp word [abs 12], 0xDD86
        je .v6
%endif
        mov edi, ebx
        call ethhdr
        mov eax, 0x00450008     ; IPv4, a header of 20 bytes, nothing special
        stosd
        scasw                   ; (the length: below)
        mov eax, 0x00400000     ; no id: never to be fragmented
        stosd
        lea eax, [rbp+20]       ; where TTL, protocol and checksum go, first the rest of the
        xchg al, ah             ; pseudo header: 0, protocol, TCP length; the addresses follow
        shl eax, 16
        mov ah, 6
        stosd
        push P_IP               ; the addresses: from ours, which is where the frame in
        pop rsi                 ; hand was sent to, to the client's;
        lodsq
        ror rax, 32
        stosq
        lodsd                   ; and the ports, which follow them there, likewise
        rol eax, 16
        stosd
        lea esi, [rbx+22]
        lea ecx, [rbp+32]
        test r8d, r8d
        jz .sum
        ; A frame for the card to cut up. The 12 bytes in front of it say so: its sums are
        ; to be made (1), it is TCP segments over IPv4 (1) behind 54 bytes of headers, TXM
        ; bytes each; a sum covers what follows byte 34 and goes 16 bytes behind that.
        ; Where the sum goes we put what is ours to add: the pseudo header's, as it is.
        mov dword [rbx-12], 0x00360101
        mov eax, [TXM]
        mov [rbx-8], ax
        mov dword [rbx-6], 0x00100022
%ifdef OURIP6
        and word [rbx-2], 0     ; (where a frame over IPv6 has had part of its header)
%endif
        push 12
        pop rcx
        call csum
        not eax
        jmp .sumd
.sum:   call csum
.sumd:  mov [rbx+50], ax
        lea ecx, [rbp+40]
        xchg cl, ch
        mov [rbx+16], cx        ; IP total length
        mov dword [rbx+22], 0x0640 ; TTL 64, TCP, checksum 0
        lea esi, [rbx+14]
        push 20
        pop rcx
        call csum
        mov [rbx+24], ax
        lea ecx, [rbp+54]
        call txgo
        popad
        ret
%ifdef OURIP6
        ; The same over IPv6 (the frame in hand came that way: `tcp6`). The header is 40
        ; bytes: IPv6, so many bytes behind it, TCP, 64 routers at most, from our address,
        ; to the client's (which the frame in hand has in three pieces). TCP's sum covers
        ; the addresses, the length, "TCP", and the segment: that is all from the length
        ; on, in another order, while the two bytes behind the length say 0 and TCP.
.v6:    lea edi, [rbx-20]
        call ethhdr
        mov eax, 0x0060DD86
        stosd
        lea eax, [rbp+20]
        xchg al, ah
        shl eax, 16
        stosd
        mov ax, 0x0600
        stosw
        mov esi, IP6
        movsq
        movsq
        push 14                 ; (bytes 14 to 25 of the frame in hand,
        pop rsi
        movsq
        movsd
        lodsd
        movsd                   ; and 30 to 33;
        lodsd                   ; the ports follow)
        rol eax, 16
        stosd
        test byte [rbx+47], 2   ; (a SYN-ACK says what a segment may hold: over IPv6 that
        jz .ns6                 ; is 20 bytes less, 1440)
        sub byte [rbx+57], 20
.ns6:   lea esi, [rbx-2]
        lea ecx, [rbp+56]
        test r8d, r8d
        jz .sum6
        ; (for the card to cut up: TCP segments over IPv6 (4) behind 74 bytes of headers;
        ; a sum covers what follows byte 54)
        mov dword [rbx-32], 0x004A0401
        mov eax, [TXM]
        mov [rbx-28], ax
        mov dword [rbx-26], 0x00100036
        push 36
        pop rcx
        call csum
        not eax
        jmp .sumd6
.sum6:  call csum
.sumd6: mov [rbx+50], ax
        mov word [rbx], 0x4006
        lea ecx, [rbp+74]
        sub ebx, 20
        call txgo
        popad
        ret

; cuts: ZF unless the card cuts frames into segments for us on the way the frame in hand
; came (IPv4: HOST_TSO4; IPv6: HOST_TSO6). Keeps all registers.
cuts:   push rax
        mov eax, 0x800
        cmp word [abs 12], 0xDD86
        jne .t
        add eax, eax
.t:     test [TSO], eax
        pop rax
        ret
%endif

; csum: eax = internet checksum of ecx bytes at esi (clobbers ecx, edx, esi).
; dec leaves CF alone, so the end-around carry rides through the loop in adc.
csum:
        xor edx, edx
.l:     lodsw
        adc dx, ax
        dec ecx
        dec ecx
        jg .l
        adc dx, 0
        not edx
        xchg eax, edx
        ret
