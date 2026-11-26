; ip6.asm: IPv6, for an image that is built with an address (OURIP6). A part of os.asm,
; which includes it.
%ifdef OURIP6
; tcp6: the frame in FR is not IPv4 (`tcp`; ebx = 0). If it is IPv6 with TCP or ICMPv6
; right behind its header (no other header in between: nobody sends TCP that way, and a
; fragment is one of those), all of it in this frame, and its checksum right, it is one
; of two things. A neighbour's question who has our address: `nd`. Or TCP for our address
; (IP6: the one the image was built with), which is made to look like the IPv4 frame that
; all of `tcp` knows, and goes on there:
;   The 40 bytes of header go, and the segment moves down the 20 bytes by which that
;   header was longer. The frame keeps its type, which says what an answer has to look
;   like (`tcp_seg`), and the client's address, in three pieces, where an IPv4 header
;   has what nobody looks at again: bytes 14 to 25, and 30 to 33. Where the client's
;   IPv4 address would be (P_IP) goes what stands for it in a slot: `find` says what.
; So the first 64 bytes of such a frame still say who the client is and how to reach it,
; which is what the timers keep of a frame (`tarm`, `tnote`).
tcp6:   cmp word [rbx+12], 0xDD86
        jne tcp.ret0
        mov al, [rbx+14]
        and al, 0xF0
        cmp al, 0x60
        jne tcp.ret0
        movzx ecx, word [rbx+18]
        xchg cl, ch             ; so many bytes behind the header
        lea eax, [rcx+54]
        cmp eax, [RXLEN]
        ja .bad
        mov ebp, [rbx+20]       ; what follows the header, and how many routers it may still pass
        mov eax, ebp
        cmp al, 6
        je .sum
        cmp al, 58
        jne .ret
.sum:   shl eax, 8              ; The checksum, TCP's or ICMPv6's, covers the addresses,
        mov [rbx+20], ax        ; the length, what follows the header, and that: all from
        mov [rbx+rcx+54], bl    ; the length on, once the two bytes behind it say 0 and
        push rcx                ; what follows. (And a zero byte after an odd length.)
        lea esi, [rbx+18]
        add ecx, 36
        call csum
        pop rcx
        test ax, ax
        jnz .bad
        mov eax, ebp
        cmp al, 58
        je nd
        cmp ecx, 20             ; (TCP's header at least: what is taken for ports must be some)
        jb .bad
        lea esi, [rbx+38]
        call our6
        jne .ret
        movdqu xmm0, [rbx+22]
        movq [rbx+14], xmm0
        pextrd [rbx+22], xmm0, 2
        pextrd [rbx+30], xmm0, 3
        or dword [rbx+P_IP], -1 ; (not nobody's)
        lea esi, [rbx+54]
        lea edi, [rbx+34]
        push rcx
        rep movsb
        pop rcx
        sub dword [RXLEN], 20
        jmp tcp.sums
.bad:   count 0                 ; (`tcp.bad` and `tcp.ret`, where what is here reaches them: but for
.ret:   ret                     ; the first two of `tcp6`, to which the `ret` at the end of `tcp` is near)

; nd: an ICMPv6 message (whole, its checksum right: `tcp6`; ecx = its length, bp = what
; followed the header and how many routers the frame may still pass). If it is a neighbour
; solicitation (135) for our address, has passed no router (255: nobody further away than
; our own link can ask), and its sender says who it is (one from "::" asks whether the
; address is free: it is not, but we don't say), it gets the advertisement: our address is
; at our card's. That is all of ICMPv6 here: no echo, and nothing that tells us about a
; router, since a frame of ours goes to where the one it answers came from.
nd:     cmp bp, 0xFF3A
        jne tcp6.ret
        cmp word [rbx+54], 135
        jne tcp6.ret
        cmp ecx, 24
        jb tcp6.ret
        lea esi, [rbx+62]
        call our6
        jne tcp6.ret
        mov rax, [rbx+22]
        or rax, [rbx+30]
        jz tcp6.ret
        call txbuf
        mov edi, ebx
        call ethhdr
        mov eax, 0x0060DD86     ; IPv6,
        stosd
        mov eax, 0x20000000     ; 32 bytes behind the header
        stosd
        mov ax, 0x3A00          ; (for the sum: 0, ICMPv6),
        stosw
        mov esi, IP6            ; from our address
        movsq
        movsq
        push 22                 ; to the asker's:
        pop rsi
        movsq
        movsq
        mov eax, 136            ; a neighbour advertisement,
        stosd
        push 0x60               ; asked for, and to be believed over what was known,
        pop rax
        stosd
        mov esi, IP6            ; for our address:
        movsq
        movsq
        mov ax, 0x0102          ; it is at this card's (option 2, 8 bytes)
        stosw
        mov esi, MAC
        movsd
        movsw
        lea esi, [rbx+18]
        push 68
        pop rcx
        call csum
        mov [rbx+56], ax
        mov word [rbx+20], 0xFF3A ; ICMPv6, which no router is to pass on
        push 86
        pop rcx
        jmp txgo

; our6: ZF if the 16 bytes at rsi are our IPv6 address (clobbers rax)
our6:   mov rax, [rsi]
        cmp rax, [IP6]
        jne .no
        mov rax, [rsi+8]
        cmp rax, [IP6+8]
.no:    ret
%endif
