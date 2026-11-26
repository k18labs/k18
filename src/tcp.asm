; tcp.asm: `tcp`, what a frame that came is and does. A part of os.asm, which includes it.
; ----------------------------------------------------------------------------
; tcp: handle the frame in FR (RXLEN bytes). FR stays as it came, except that its sequence
; number and ack are turned into host order (P_SEQ, P_ACK); what we send is built in the
; transmit buffers (`tcp_seg`).
;
; Each connection knows the next byte it expects from the client (C_NXT), our next byte
; (C_SND) and the client's last ack (C_ACK). What we have sent is never stored, except the
; handshake flight: everything else is made again from what never changes. On port 443
; that is the response in hand, a stretch of the image, sealed a record to a segment
; (`.tx` has how it is sent and sent again). On port 80 it is one response for every
; request, and with the flight it goes the old way: anything the client turns out not to
; have is built again from the byte its ack names and sent at once (`.resend`), and two
; things tell us that a packet of ours was lost:
;   - the client sends old data again, with an ack below C_SND: its request is not
;     acknowledged because the answer, which carries our ack, did not arrive;
;   - the client repeats an ack below C_SND without data: it got something after a hole.
; So that the first always works, an answer of several segments does not acknowledge the
; client's data (`tcp_send`): that happens when the client's ack says it has all of it.
;
; Connections live in two hashed tables (`find`): one for port 443, one with small slots for
; port 80, which has no TLS and no files (a request ends with an empty line and gets the
; one response). A SYN gets a SYN-ACK and no slot (`.syn`); the first packet that
; acknowledges it makes the connection. A segment that comes before its predecessor is
; kept (`oohold`).
tcp:
        xor ebx, ebx            ; FR (and 0), all the way through
        cmp word [rbx+12], 0x0608
        jne .ip
        cmp dword [rbx+RXLEN], 42 ; ARP, and all of it (what lies behind a shorter frame is
        jb .ip                  ; the frame before it): a request for our address is answered
        cmp word [rbx+20], 0x0100 ; (Any other goes on to `.ip`, which is near, and where
        jne .ip                 ; a frame of this type gets no further.)
        NOTOURS rbx+38, .ip
        call txbuf
        mov edi, ebx
        call ethhdr
        push 12                 ; the request's type and header up to the operation,
        pop rsi
        push 9
        pop rcx
        rep movsb
        mov al, 2               ; which is: reply. We are its sender,
        stosb
        mov esi, MAC
        movsd
        movsw
        push 38                 ; with the address that was asked for;
        pop rsi
        movsd
        push 22                 ; the request's sender is its target
        pop rsi
        mov cl, 10
        rep movsb
        mov cl, 42
        jmp txgo
.ip:    cmp word [rbx+12], 0x0008 ; IPv4, no options, not a fragment, TCP, to us, all of it
%ifdef OURIP6                   ; (what is not IPv4 may be IPv6, where we have an address
        jne tcp6                ; for that: `tcp6`)
%else
        jne .ret
%endif
                                ; in this frame, the TCP checksum right: nothing else gets
        cmp byte [rbx+14], 0x45 ; any further. (The IP header has a checksum of its own, but
        jne .ret                ; what we use of it is fixed here or goes into TCP's.)
        test word [rbx+20], 0xFF3F
        jnz .ret
%ifndef OURIP                   ; (Or, where our address is somebody's to give: UDP, to
        cmp byte [rbx+23], 17   ; whatever address, all of it in this frame: it may be what
        je .len                 ; a DHCP server says, `dhcp`.)
%endif
        cmp byte [rbx+23], 6
        jne .ret
        NOTOURS rbx+30, .ret
.len:   movzx ecx, word [rbx+16]
        xchg cl, ch             ; IP total length
        lea eax, [rcx+14]
        cmp eax, [RXLEN]
        ja .bad
        cmp ecx, 40             ; (our header and TCP's at least: asked before the one is
        jb .bad                 ; taken off, or a length of less than 20 would pass as 4 GiB)
        sub ecx, 20             ; TCP length
        mov [rbx+22], bl        ; the pseudo header, in place: 0, protocol, TCP length, addresses
        mov eax, ecx
        xchg al, ah
        mov [rbx+24], ax
        mov [rbx+rcx+34], bl    ; (a zero byte after an odd length)
        push rcx
        lea esi, [rbx+22]
        add ecx, 12
        call csum
        pop rcx
%ifndef OURIP
        cmp byte [rbx+23], 17
        je dhcp
%endif
        test ax, ax
        jz .sums
.bad:   count 0
.ret:   ret
.sums:
        cmp word [rbx+36], 0xBB01 ; port 443: TLS
        je .port
        cmp word [rbx+36], 0x5000 ; port 80: the same without
        jne .ret
.port:  cmp [rbx+P_IP], ebx     ; (no client is 0.0.0.0: that marks a free slot)
        je .ret
        movzx eax, byte [rbx+46]
        shr eax, 2
        and al, 0x3C            ; TCP header length
        cmp al, 20
        jb .ret
        sub ecx, eax            ; payload length
        jb .ret
        lea esi, [rbx+rax+34]   ; payload
        mov eax, [rbx+P_SEQ]
        bswap eax
        mov [rbx+P_SEQ], eax
        mov eax, [rbx+P_ACK]
        bswap eax
        mov [rbx+P_ACK], eax
        call clock
        mov [rbx+P_MORE], bx    ; (and P_EV)
        mov dl, [rbx+P_FL]
        call find               ; ebp = the connection's slot; or, if it has none, eax = -1
        sbb eax, eax            ; and ebp = a slot for a new one (0: there is no room)
        jnz .slot
        call hold               ; Its slot, which is in use from here on (`hold`): unless
        jne .gone               ; another processor has just made it its own, and then
        xor eax, eax            ; this packet is as good as lost
.slot:  test dl, 4
        jz .nrst
        inc eax                 ; RST: if it is where our acks have said its connection is
        jz .ret                 ; (`ackno`: one number, and the one a host has that knows
        call ackno              ; no more of the connection than our segments), that was
        cmp edi, [rbx+P_SEQ]    ; the connection
        jne .ret
.free:  and dword [rbp+C_IP], 0
.gone:  ret
.nrst:  test dl, 2
        jz .nsyn
        test dl, 16
        jnz .ret
        ; SYN. It gets a SYN-ACK and no slot: the slot is made when an ack shows that the
        ; client received it (`.miss`), so only clients that really are at their address can
        ; take up slots. For that our initial sequence number is a "cookie", made of W, a
        ; keyed hash of the client's address and ports (`prf`):
        ;   bits 14-31: W xor the low bits of the client's initial sequence number, so that
        ;               the packet that follows the SYN-ACK is recognised as the first;
        ;   bits 6-13:  W (HINT): tells a packet that acknowledges a SYN-ACK of ours, first
        ;               or not, from one of a connection we don't know;
        ;   bits 2-5:   by how many bits the client shifts its window (window scaling:
        ;               what its SYN said, 14 at most; 0: it does not);
        ;   bits 0-1:   which of four segment sizes the client takes (MSSTAB).
        inc eax
        jz .nos
        or byte [rbp+C_FLG], F_SYN ; (for a connection we have: its client may be starting
        jmp .syn                ; over, see `.odd`)
.nos:   test rbp, rbp
        jz .deny                ; (no room where this connection would go: say so now)
.syn:   lea ecx, [rsi-54]       ; its options (they end where what it carries begins: esi):
        lea esi, [rbx+54]       ; how much the client takes in one segment, and whether it
                                ; scales its window
        mov edx, 536            ; (what one that doesn't say must take)
        xor r8d, r8d
.opt:   cmp ecx, 2
        jl .optd
        lodsb
        dec ecx
        cmp al, 1               ; padding
        je .opt
        jb .optd                ; end of options
        movzx edi, byte [rsi]   ; length of this one, with the two bytes that say so
        dec edi
        jle .optd
        cmp edi, ecx
        ja .optd
        cmp al, 2
        jne .ows
        cmp edi, 3
        jne .onx
        movzx edx, word [rsi+1]
        xchg dl, dh
        cmp edx, 216            ; (One that takes less than our smallest segment is told
        jb .deny                ; no: it is not sent more than it said. RFC 9293, 3.7.1)
.ows:   cmp al, 3               ; (window scale: a shift, of which 14 is the most there is)
        jne .onx
        cmp edi, 2
        jne .onx
        movzx r8d, byte [rsi+1]
        cmp r8d, 14
        jbe .onx
        mov r8b, 14
.onx:   add esi, edi
        sub ecx, edi
        jmp .opt
.optd:  call tnote
        movzx ecx, word [rbx+P_WIN] ; (And no more in one segment than it takes at all, which a
        xchg cl, ch             ; SYN says unshifted: a segment goes whole or not at all, and
        cmp edx, ecx            ; one that its window never holds would go only when we ask
        cmova edx, ecx          ; what it takes: `.tx`, `tqrun`.)
        mov eax, [rbx+P_SEQ]
        lea edi, [rax+1]        ; (the SYN takes a sequence number, and so does ours)
        shl eax, 14
        xor eax, [HKO+8]
        and al, 0xC0
%ifdef ISNTOP                   ; (make ISNTOP=n ISNBITS=b, for tests: the top b bits of
        and eax, ISNLOW         ; every initial sequence number are n's, so that what we
        or eax, ISNTOP & ~ISNLOW ; send crosses 2^31 or 2^32 soon. The cookie then says
%endif                          ; that much less: see `ckx`)
        cmp edx, 536            ; the largest of the four sizes that is not more than the
        sbb eax, -1             ; client's
        cmp edx, 1220
        sbb eax, -1
%ifdef OURIP6                   ; (Over IPv6, 1220 is the most: with its headers that is
        cmp word [rbx+12], 0xDD86 ; the 1280 bytes every link of IPv6 has to carry, so no
        je .six                 ; path is too narrow for a segment of ours, and nobody
%endif                          ; has to tell us that one was: nobody is listened to.)
        cmp edx, 1440
        sbb eax, -1
.six:   lea eax, [rax+r8*4]
        xchg eax, edx
        mov al, 0x12            ; SYN|ACK. Its options: what we take in one segment, and, if
        mov esi, SYNOPT         ; the client scales its window, that we know (and don't
        push 4                  ; scale ours: 64 KB at a time is more than any request)
        pop rcx
        test r8d, r8d
        jz .seg
        mov cl, 8
.seg:   jmp tcp_seg
.deny:  count 2
        mov al, 0x14            ; RST|ACK: connection refused
        mov edi, [rbx+P_SEQ]
        inc edi
        xor edx, edx
        xor ecx, ecx
        jmp .seg

.nsyn:  test dl, 16
        jz .ret2
        inc eax
        jnz .est
        ; No such connection. If this is the first packet after one of our SYN-ACKs, it is a
        ; new one, in the slot `find` chose. If it acknowledges a SYN-ACK of ours but is not
        ; the first (that one got lost, and its ack before it), the client will send the
        ; first again: nothing to do. Anything else that expects an answer is told that there
        ; is no connection (after a FIN we forget at once; and we may have been restarted).
.miss:  call ckx
        jz .make
        test ax, HINT
        jz .ret2
        test dl, 1
        jnz .rst
        test ecx, ecx
        jz .ret2
.rst:   count 5
        mov al, 4               ; RST, where the client's ack says
        mov edx, [rbx+P_ACK]
        xor ecx, ecx
        xor edi, edi
        jmp .seg
.ret2:  ret
.full:  count 2                 ; there is no room for it: refused
        jmp .rst
.make:  test rbp, rbp
        jz .full
        movzx edi, byte [NOW]   ; The slot becomes this connection's in one step, if it still
        shl edi, 24             ; is as `find` saw it: another processor may have taken it
        mov di, [rbx+P_PORTS]   ; since, for a connection of its own. (Then this packet is as
        shl rdi, 32             ; good as lost, and will come again.) Its first eight bytes:
        mov eax, [rbx+P_IP]     ; the client's address and port, no flags, and the time
        or rdi, rax             ; (C_AGE): from that step on it is not one that has long
        mov rax, [CLAIMQ]       ; been quiet, for anybody to take
        lock cmpxchg [rbp], rdi
        jne .ret2
        mov eax, [HKO+12]       ; (its SYN-ACK has arrived: `tnote`)
        and eax, [TMMASK]
        mov edi, [TMT]
        mov [rdi+rax*4], ebx
        push rcx
        lea rdi, [rbp+8]
        push (PSLOT - 8) / 4
        pop rcx
        cmp [rbx+P_PORTS+2], bl
        je .mk
        mov cl, (C_KIV - 8) / 4 ; (a slot of the TLS table goes on)
.mk:    xor eax, eax
        rep stosd
        pop rcx
        mov eax, [rbx+P_SEQ]
        mov [rbp+C_NXT], eax
        mov eax, [rbx+P_ACK]
        lea edx, [rax-1]        ; What the SYN-ACK noted in our sequence number: the client's
        shl edx, 2              ; window shift (the top four bits of C_FL2; in a slot for
        mov dh, dl              ; port 80, which ends before that, rdi-2 is in the spare four
        and dh, 0xF0            ; bytes at its end) and its segment size
        mov [rdi-2], dh
        and dl, 0x0C
%ifdef OURIP6                   ; (Over IPv6 it is 1,220 bytes at most, see `.syn`, also for
        cmp dl, 0x0C            ; a client whose ack says that our SYN-ACK noted more: what
        jne .cl                 ; the SYN-ACK noted is the client's to send back, or not.)
        cmp word [rbx+12], 0xDD86
        jne .cl
        mov dl, 8
.cl:
%endif
        mov [rbp+C_FLG], dl
        mov [rbp+C_SND], eax
        mov [rbp+C_ACK], eax

        ; Whose segment it is. The client's begins within what we take at once (64 KB)
        ; of what we expect next, before it or behind: early, late, or sent again. And
        ; its ack counts if it is in [C_ACK, C_SND]. (What else there can be, and what
        ; becomes of it: `.odd`.) edx = 1: it lacks something we sent, 2: and says so
        ; with the same ack as before, 0: neither
.est:   xor edx, edx
        mov [rbx+P_ADV], edx
        mov eax, [rbx+P_SEQ]
        sub eax, [rbp+C_NXT]
        add eax, 0x10000
        shr eax, 17
        jnz .oseq
        mov eax, [rbx+P_ACK]
        sub eax, [rbp+C_ACK]    ; how much further than before
        mov edi, [rbp+C_SND]
        sub edi, [rbp+C_ACK]    ; how much there is to acknowledge
        cmp eax, edi
        ja .oack
        jb .ak0
        test byte [rbp+C_FLG], F_CLOSED ; It has all we sent. If that includes our FIN, that
        jz .nfin                ; was the connection
        cmp [rbx+P_PORTS+2], bl
        je .free2
        test byte [rbp+C_FL2], F_FIN
        jnz .free2
.nfin:  cmp [rbx+P_PORTS+2], bl
        je .nhs
        cmp [rbp+C_ST], ebx
        je .nhs
        mov edi, [rbp+C_T0]     ; It has our flight. The first time: how long that took is
        test edi, edi           ; the round trip R (the client answers a flight at once: it
        jz .rtt                 ; has its Finished to send), and the timer for what we send
        mov [rbp+C_T0], ebx     ; from now on (`tarm`) waits 3 R (TCP's own rule after one
        neg edi                 ; measurement, RFC 6298), but a quarter of a second at
        add edi, [TNOW]         ; least, which is what it waits while the round trip is
        shr edi, 5              ; not known, and a second at most: a flight that had to go
        lea edi, [rdi+rdi*2]    ; twice took longer than the round trip, by the client's
        cmp edi, 16             ; own timer, and a timer made of that would leave what is
        jae .r16                ; lost at the end of a response lying for seconds. (In
        mov dil, 16             ; units of 1/64 s.)
.r16:   cmp edi, 64
        jbe .r64
        mov dil, 64
.r64:   mov [rbp+C_RTO], dil
.rtt:   cmp [rbp+C_LEN], bx
        jne .nhs
        mov [rbp+C_HS], bx      ; (And no record of its own is being put together: the
.nhs:   btr dword [rbp+C_FLG], F_DEFER_BIT ; handshake buffer can go to another)
                                ; If that was an answer of several segments, its
        jnc .ak1                ; data is acknowledged only now
        inc byte [rbx+P_MORE]
        jmp .ak1
        ; Not this connection's segment as it stands: its sequence number is not where
        ; the client's are (`.oseq`), or its ack is not for something we sent that is
        ; still to be acknowledged (`.oack`). Three things it can be:
        ;   - The first packet of a new connection from the same address and port, whose
        ;     predecessor we never saw end: if it is the cookie of a SYN-ACK of ours.
        ;     Only if a SYN has come: a late copy of this connection's own first ack is
        ;     a valid cookie too, and must not start it over.
        ;   - A packet of the client's that others overtook: where its sequence numbers
        ;     are, with an ack from before its last one, by less than can have been on
        ;     its way at once (255 segments, C_CW's most: under 2^19 bytes). Its ack
        ;     says nothing; what it carries counts.
        ;   - Not the client's. Nothing of it is taken: not its ack, not its data, not
        ;     its FIN, not what it says the client takes. So whoever sends in a client's
        ;     name without seeing what we send it has two numbers to guess, where the
        ;     client's are and where ours are, for anything at all to come of it (RFC
        ;     9293, 3.10.7.4: the sequence number first; RFC 5961, 5.2: and the ack).
        ;     It gets an ack, which says where we are, as RFC 9293 has it for every
        ;     segment that is not what is expected (one for one, with no count kept of
        ;     them: a count is something an outsider can read).
.oack:  neg eax                 ; (how far behind the client's last ack)
        shr eax, 19
.oseq:  xchg eax, edi           ; edi = 0: only its ack is old
.odd:   test byte [rbp+C_FLG], F_SYN
        jz .stale
        call ckx
        jnz .stale
        mov rax, [rbp]
        mov [CLAIMQ], rax
        jmp .make
.free2: and dword [rbp+C_IP], 0 ; (`.free`, where `.est` reaches it)
        ret
.stale: test edi, edi
        jz .ak
.bare:  xor ecx, ecx            ; (an ack and nothing else, from where we are)
        mov al, 0x10
        mov edx, [rbp+C_SND]
        call ackno
        jmp tcp_seg
.ak0:   inc edx
        test eax, eax
        jnz .ak1
        inc edx
.ak1:   add [rbp+C_ACK], eax
        mov [rbx+P_ADV], eax
        and byte [rbp+C_FLG], ~F_SYN
.ak:    test byte [rbp+C_FLG], F_CLOSED
        jz .open
        test edx, edx           ; Closed: nothing more is taken from the client. If it lacks
        jz .quiet               ; something (our FIN at least) and asks, by sending anything
        cmp dl, 2               ; but a plain new ack, it gets that again
        je .resend
        test byte [rbx+P_FL], 1
        jnz .resend
        test ecx, ecx
        jnz .resend
.quiet: call sm                 ; Nothing to say. But if a response is on its way, the ack
        jc .tx                  ; may have made room for more of it
        ret
.open:  mov eax, [rbp+C_NXT]
        sub eax, [rbx+P_SEQ]    ; how many of this segment's bytes we already have
        js .early
        jz .inord
        cmp eax, ecx
        ja .old
        jb .trim
        test byte [rbx+P_FL], 1 ; all of its data is old; a FIN after it would be new
        jz .old
.trim:  add esi, eax            ; drop what we have, the rest is new
        sub ecx, eax
        jmp .new
.early: count 3                 ; From further on (inside our window: `.est`): what comes
                                ; before it is late (neighbours do get swapped on the way)
                                ; or lost. Keep it for when that arrives, if it is not
                                ; empty, and say what we expect.
        mov al, [rbx+P_FL]
        and eax, 1
        or eax, ecx
        jnz .keep
        cmp dl, 2               ; (An empty one whose ack repeats says of what we sent
        jne .ack                ; what such an ack says from where we expect the client:
        or byte [rbx+P_EV], E_DUP ; `.tx`. A client is further on for as long as a
        jmp .ack                ; request of its waits to be sent again: `.busy`.)
.keep:  call oohold
        jmp .ack
.old:   jrcxz .ack              ; (a keep-alive probe: one byte back, no data)
        test edx, edx           ; old data again. If the client lacks something of ours, that
        jnz .resend             ; is why; if not, an ack will do
.ack:   call sm
        jc .txa
        and byte [rbx+P_FL], ~1
        mov edi, OB
        mov eax, [rbp+C_SND]
        cmp eax, [rbp+C_ACK]
        je .reply
        jmp .out
        ; The client lacks the end of what we sent, from its ack on. If a response is on
        ; its way, `.tx` sees to it; if not, `.lres`. (It stands here, among those that
        ; come to it, so that their jumps are short ones.)
.resend:
        call sm
        jnc .lres
        mov al, E_DUP
        test byte [rbx+P_FL], 1
        jnz .lost
        jrcxz .ev
.lost:  mov al, E_RTO | E_ACK
.ev:    or [rbx+P_EV], al
        jmp .tx
.inord: test ecx, ecx
        jnz .new
        test byte [rbx+P_FL], 1
        jnz .new
        cmp dl, 2               ; no data: an ack. The same ack twice with something
        je .resend              ; outstanding: a segment of ours is missing
        cmp [rbx+P_MORE], bl
        jne .ack
        jmp .quiet

.new:   mov edi, OB             ; edi = end of our answer
.more:  add [rbp+C_NXT], ecx    ; ecx new bytes at esi, in order
        cmp [rbx+P_PORTS+2], bl
        je .plain
        mov [SEGP], esi
        ; TLS: records. One that is all in this segment is looked at where it is (`record`).
        ; One that is not (and every ClientHello, whose buffer our flight will need) is put
        ; together in a handshake buffer: C_LEN bytes of it are there. Its header says how
        ; long it is; if that is more than the buffer holds, we can't go on.
.walk:  test byte [rbp+C_FLG], F_CLOSED ; (a client we are done with gets nothing more taken
        jnz .out                ; from it)
        test ecx, ecx
        jz .reply
        movzx eax, word [rbp+C_LEN]
        test eax, eax
        jnz .part
        cmp [rbp+C_ST], ebx
        je .coll
        cmp ecx, 5
        jb .coll
        movzx edx, word [rsi+3]
        xchg dl, dh
        add edx, 5              ; the record's length
        cmp edx, ecx
        ja .coll
        call record
        jc .busy
        add esi, edx
        sub ecx, edx
        jmp .walk
.coll:  push rbx
        call hsnew
        jmp .buf
.part:  push rbx
        call hsbuf
        jc .resetp              ; (its first part is gone: the buffer was needed for others)
.buf:   push 5
        pop rdx
        cmp eax, edx
        jb .take                ; (first its header)
        movzx edx, word [rbx+HS_CH+3]
        xchg dl, dh
        add edx, 5
        cmp edx, CHMAX
        ja .resetp
.take:  sub edx, eax            ; so many bytes are wanted,
        cmp edx, ecx
        jbe .tk
        mov edx, ecx            ; and so many are here
.tk:    push rcx
        push rdi
        lea edi, [rbx+HS_CH+rax]
        mov ecx, edx
        rep movsb
        pop rdi
        pop rcx
        sub ecx, edx
        add eax, edx
        mov [rbp+C_LEN], ax
        cmp eax, 5
        jb .nyet
        movzx edx, word [rbx+HS_CH+3]
        xchg dl, dh
        add edx, 5
        cmp eax, edx
        jb .nyet
        cmp dword [rbp+C_ST], 0 ; all there. Before the handshake it is the ClientHello, if
        jne .rec                ; it is a handshake record at all (clients send a
        cmp byte [rbx+HS_CH], 22 ; ChangeCipherSpec before a second ClientHello, for
        jne .done               ; middleboxes' sake: nothing to us);
.hello: push rsi                ; (the rest of this segment)
        push rcx
        push rbx
        lea esi, [rbx+HS_CH+5]
        lea ecx, [rdx-5]
        call handshake          ; edi = end of our flight
        pop rbx
        mov ecx, edi            ; keep the flight, where the ClientHello was: a client that
        sub ecx, OB             ; sends its ClientHello again has to get this one again (it
        mov [rbx+HS_FLEN], ecx  ; may have got it already)
        mov eax, [rbp+C_SND]
        add eax, ecx
        mov [rbp+C_RS], eax     ; (behind it our responses will begin)
        mov eax, [TNOW]         ; (And from now to the client's answer is the connection's
        mov [rbp+C_T0], eax     ; round trip, which its timer goes by: `.est`. Until that
        mov byte [rbp+C_RTO], 16 ; is known: a quarter of a second.)
        push rdi
        mov esi, OB
        lea edi, [rbx+HS_FL]
        rep movsb
        pop rdi
        pop rcx
        pop rsi
.done:  pop rbx                 ; That was the record: the next one begins
.done0: mov [rbp+C_LEN], bx
        jmp .walk
.rec:   push rsi
        lea esi, [rbx+HS_CH]
        call record             ; any other is looked at like those that come in one piece
        pop rsi
        pop rbx
        jc .busyc
        mov [rbp+C_HS], bx      ; (and the buffer can go to another)
        jmp .done0
.nyet:  pop rbx
        jmp .walk
        ; A request whose response can't be the one in hand yet (`record`): it is as good
        ; as not arrived, and so is all that follows it in this segment. The client will
        ; send it again.
.busyc: mov eax, esi            ; (one put together: this segment's part of it leaves the buffer)
        sub eax, [SEGP]
        sub [rbp+C_LEN], ax
        add ecx, eax
.busy:  sub [rbp+C_NXT], ecx
        and byte [rbx+P_FL], ~1
        jmp .out

        ; Port 80. A request ends with an empty line (the top bit of C_FLG: the last line
        ; has just ended; CRs don't count either way) and gets the response, while nothing
        ; sent before is unacknowledged and at most 4 KiB go in this turn: any more are
        ; kept (`oohold`) for the ack, so a small ack cannot ask for 256 KiB at a time.
.plain: test ecx, ecx
        jz .reply
        mov eax, [rbp+C_SND]
        cmp eax, [rbp+C_ACK]
        jne .pwait
        movzx edx, byte [rbp+C_FLG]
        shr edx, 7
.hb:    lodsb
        cmp al, 13
        je .hn
        cmp al, 10
        jne .h0
        inc edx
        cmp dl, 2
        jb .hn
%if P80_LEN <= 4096
        cmp edi, OB + 4096 - P80_LEN
        ja .pbusy
%else
        cmp edi, OB
        jne .pbusy
%endif
        call respond
.h0:    xor edx, edx
.hn:    loop .hb
        and byte [rbp+C_FLG], 0x7F
        shl edx, 7
        or [rbp+C_FLG], dl
        jmp .reply
.pbusy: dec esi
        or byte [rbp+C_FLG], 0x80
.pwait: sub [rbp+C_NXT], ecx
        mov eax, [rbp+C_NXT]
        xchg eax, [rbx+P_SEQ]
        call oohold
        and byte [rbx+P_FL], ~1
        cmp edi, OB
        jne .out
        cmp eax, [rbp+C_NXT]
        je .out
        mov eax, [rbx+P_ACK]
        cmp eax, [rbp+C_ACK]
        je .resend
        jmp .out

.reply: xor ebx, ebx
        call ooent              ; Is a segment that came early next now? Then go on with it.
        jne .out
        mov eax, [rbp+C_NXT]
        sub eax, [rdx+OO_SEQ]   ; how many of its bytes we have by now
        js .out                 ; (it is still ahead)
        mov [rdx+OO_TAG], ebx
        mov ecx, [rdx+OO_LEN]
        cmp eax, ecx
        ja .out
        jb .use
        cmp [rdx+OO_FIN], bl    ; (all of its data came another way; a FIN after it is new)
        je .out
.use:   test byte [rbx+P_FL], 1
        jnz .out                ; (nothing follows a FIN)
        lea esi, [rdx+OO_DATA+rax]
        sub ecx, eax
        mov al, [rdx+OO_FIN]
        or [rbx+P_FL], al
        jmp .more
.out:   call sm
        jc .txo
        mov esi, OB             ; our answer is at OB, up to edi; it follows what we sent before
        mov ecx, edi
        sub ecx, esi
        mov al, 0x10            ; ACK
        jz .fin
        mov al, 0x18            ; ACK|PSH
.fin:   test byte [rbp+C_FLG], F_CLOSED ; (our answer was "no": `handshake`. We close)
        jnz .ours
        test byte [rbx+P_FL], 1
        jz .send
        inc dword [rbp+C_NXT]   ; the client's FIN takes a sequence number and gets ours with
.ours:  or al, 1                ; the answer
.send:  mov edx, [rbp+C_SND]
        add [rbp+C_SND], ecx
        test al, 1
        jz .sq
        inc dword [rbp+C_SND]   ; (ours takes one too)
        or byte [rbp+C_FLG], F_CLOSED
        cmp [rbx+P_PORTS+2], bl
        je .f80
        or byte [rbp+C_FL2], F_FIN
.f80:   mov edi, [rbx+P_ACK]    ; If the client had all we sent and there was nothing more to
        sub edi, edx            ; say, that was the connection (should our FIN get lost, the
        or edi, ecx             ; client's next one is told that there is none). If not, the
        jnz .sq                 ; slot stays until the client has the rest.
        call tcp_send
        jmp .free
.sq:    jmp tcp_send

        ; A TLS connection whose client has had our flight (`sm`). What we send from then
        ; on is cut from the response in hand, which is a stretch of the image (`geom`):
        ; a record of it to a segment, so that any segment can be made again from nothing
        ; but where the response began (C_RS), which record that was (C_SR) and the
        ; client's ack. The client's acks let the next segments go: as many may be on
        ; their way as the client takes (its window) and as C_CW says, which begins at WIN
        ; and grows with what is acknowledged until something is lost, is halved then, and
        ; grows slowly after that (TCP's congestion control, in a byte). What tells us
        ; that a segment was lost:
        ;   - an ack that repeats: once, if two segments or less are on their way (no more
        ;     such acks can come), else three times (neighbours get swapped on the way,
        ;     and that looks the same). The segment it asks for goes again, once;
        ;   - then, an ack that moves on by no more than that segment: the one after it
        ;     was lost too (had it arrived, the ack would have gone past it);
        ;   - the client sending old data again (it waits for our ack: `tcp_send`), and
        ;     time passing without an ack (`tqrun`).
        ; A client's request for the next response waits until it has acknowledged all of
        ; this one (`record`), so one response is all a connection has to know of.
.txo:   test byte [rbx+P_FL], 1
        jz .txa
        inc dword [rbp+C_NXT]   ; the client's FIN: ours follows what it still has to get
        or byte [rbp+C_FLG], F_CLOSED
        and byte [rbp+C_FLG], ~F_DEFER
.txa:   or byte [rbx+P_EV], E_ACK
.tx:    call geom
        mov eax, [rbp+C_SND]
        sub eax, [rbp+C_ACK]    ; so much is on its way
        mov dl, [rbx+P_EV]
        test dl, E_RTO
        jnz .loss
        test dl, E_DUP
        jz .adv
        test eax, eax
        jz .pump
        mov ecx, [TXM]
        cmp byte [rbp+C_FLG], F_DUP3
        jae .took               ; (what it asks for has gone again already)
        add byte [rbp+C_FLG], F_DUP
        add ecx, ecx
        cmp eax, ecx
        jbe .loss
        cmp byte [rbp+C_FLG], F_DUP3
        jb .pump
        jmp .loss
        ; What it asks for has gone again already. But a segment that went to a client
        ; who takes nothing (`tqrun` sends one, to hear what it takes by now) was not
        ; lost, it was not taken: and when the client reads again, it says so with the
        ; ack it had. If a segment is all that is on its way and this ack takes it, it
        ; goes once more. (An ack that does not take it gets nothing: so the two of us
        ; never go round in a circle. And only one segment: where more are on their way,
        ; the acks that repeat are for those that arrived behind a lost one.)
.took:  cmp eax, ecx
        ja .pump
        xchg eax, edx
        movzx eax, word [rbx+P_WIN]
        xchg al, ah
        mov cl, [rbp+C_FL2]
        shr cl, 4
        shl eax, cl
        cmp eax, edx
        jae .rtx
        jmp .pump
.adv:   mov ecx, [rbx+P_ADV]
        test ecx, ecx
        jz .pump
        cmp byte [rbp+C_FLG], F_DUP3
        jb .clr
        test eax, eax           ; (After a loss: its ack has moved on, but not to the end of
        jnz .rtx                ; what was on its way then, and nothing has been sent
                                ; since: what it asks for now was lost as well)
.clr:   and byte [rbp+C_FLG], ~F_DUP3
        movzx edi, byte [rbp+C_CW] ; The ack moved on, and nothing seems lost: more may
        imul edi, [TXM]         ; be on its way. As long as nothing ever was lost, and less
        shr edi, 16             ; than 64 KB may be: as many segments more as were
        jnz .ai                 ; acknowledged (twice as many each round trip);
        test byte [rbp+C_FL2], F_CA
        jnz .ai
        xchg eax, ecx
        xor edx, edx
        div dword [TXM]
        jmp .grow
.ai:    mov eax, [rbp+C_ACK]    ; after that, one more for every 16 KiB acknowledged; and
        mov edx, eax            ; above 64 KB, for every 64 KiB (a segment or a few more
        sub edx, ecx            ; each round trip: where that is one too many, few are
        xor eax, edx            ; lost, and each of those takes a round trip to make good)
        shr eax, 14
        test edi, edi
        jz .a16
        shr eax, 2
.a16:   test eax, eax
        jz .pump
        push 1
        pop rax
.grow:  movzx edx, byte [rbp+C_CW]
        add eax, edx
        cmp eax, 255
        jbe .cw
        mov al, 255
.cw:    mov [rbp+C_CW], al
        jmp .pump
.loss:  shr byte [rbp+C_CW], 1  ; Something was lost: half as many may be on their way
        cmp byte [rbp+C_CW], 2  ; from now on (two at least)
        jae .ca
        mov byte [rbp+C_CW], 2
.ca:    or byte [rbp+C_FL2], F_CA
.rtx:   or byte [rbp+C_FLG], F_DUP3
        count 4
        mov eax, [rbp+C_ACK]
        call sendseg
.pump:  movzx eax, word [rbx+P_WIN]
        xchg al, ah             ; what the client takes beyond its ack (shifted as its SYN
        mov cl, [rbp+C_FL2]     ; said; but once something has been lost on a connection,
        shr cl, 4               ; no more than 64 KB, which was all there could be before
        shl eax, cl             ; windows were scaled: beyond it we only feel our way
        test byte [rbp+C_FL2], F_CA ; while nothing is lost),
        jz .wf
        mov edx, 0xFFFF
        cmp eax, edx
        cmova eax, edx
.wf:    mov ecx, [TXM]
        movzx edx, byte [rbp+C_CW]
        imul edx, ecx           ; and what we let be on its way
        cmp eax, edx
        cmova eax, edx
        add eax, [rbp+C_ACK]
        mov [TXLIM], eax
        mov edx, [rbp+C_SND]    ; At the start of a response that takes several segments
        cmp edx, [rbp+C_RS]     ; and goes at once: the last byte the client sent is not
        jne .pl                 ; acknowledged before it has them all (see `tcp_send`)
        test byte [rbp+C_FLG], F_CLOSED
        jnz .pl
        mov edx, [TXEND]
        sub eax, edx
        js .pl
        sub edx, [rbp+C_RS]
        cmp edx, ecx
        jbe .pl
        shr edx, 16             ; (and no more than 64 KB: a longer one is on its way for
        jnz .pl                 ; longer than a client waits for an ack before it asks again)
        or byte [rbp+C_FLG], F_DEFER
.pl:    cmp byte [rbp+C_FLG], F_DUP3 ; (While the client lacks something that was on its
        jae .pa                 ; way, nothing new goes: so its ack says when it has it all)
        mov eax, [rbp+C_SND]
        mov edx, eax
        sub edx, [TXEND]
        jns .pd                 ; (all of it has gone)
        mov edx, eax
        sub edx, [TXLIM]
        jns .pa                 ; (the client takes no more for now)
        neg edx                 ; So much more it takes. A record goes whole or not at all,
        mov ecx, [TXEND]        ; and none that would reach further: a client need not take
        sub ecx, eax            ; a segment that does (Linux drops it whole), and then it
        cmp ecx, edx            ; is lost where nothing was. So: the rest of the response
        jbe .go                 ; if it takes all of that; if not, a segment's worth at
        cmp edx, [TXM]          ; least, or it waits until the client takes one (which its
        jb .pa                  ; next ack says, or `tqrun` asks).
%ifdef OURIP6
        call cuts
%else
        cmp byte [TSO], 0       ; Where the card cuts frames for us, a frame should be worth
%endif
        je .go                  ; it. If what may go now is less than a third of what may
        lea ecx, [rdx+rdx*2]    ; be on its way at all, and not the response's end, it
        mov edi, [TXLIM]        ; waits for the acks that are to come. (A small frame
        sub edi, [rbp+C_ACK]    ; brings a small ack, which lets a small frame go: with
        cmp ecx, edi            ; that, a full window sends three segments at a time, and
        jb .pa                  ; as many frames a second as without any of this.)
.go:    call sendrun
        jmp .pl
.pd:    jnz .pa
        test byte [rbp+C_FLG], F_CLOSED
        jz .pa
        call sendseg            ; (and our FIN, if it did not go with the last of it)
.pa:    test byte [rbx+P_EV], E_SENT
        jnz .owed
        test byte [rbx+P_EV], E_ACK
        jz .owed
        call .bare              ; nothing went that carries our ack: a bare one
.owed:  mov eax, [TXEND]        ; Is the client owed anything now?
        test byte [rbp+C_FL2], F_FIN
        jz .nf
        cmp eax, [rbp+C_ACK]    ; If all it lacks is our FIN, that was the connection (should
        je .free                ; the FIN get lost, the client's own is told that there is none)
        inc eax
.nf:    cmp eax, [rbp+C_ACK]
        je .ret1
        test byte [rbp+C_FL2], F_ARMED
        jz tarm                 ; then it waits for an ack, and not for ever
.ret1:  ret

        ; What the client lacks (`.resend`) while no response is on its way: what we sent
        ; is our flight, or on port 80 the same response for every request: built again
        ; and sent, all the client lacks.
.lres:  count 4
        mov edi, OB
        mov eax, [rbp+C_SND]
        sub eax, [rbx+P_ACK]    ; so many bytes (our FIN, if it lacks that, is not one)
        test byte [rbp+C_FLG], F_CLOSED
        jz .rsz
        dec eax
.rsz:   xor esi, esi
        cmp [rbx+P_PORTS+2], bl
        je .recs
        test eax, eax
        jz .none
        push rbx
        call hsbuf              ; the end of the flight, which is in the handshake buffer,
        jc .resetp              ; unless that has gone to another connection since
        mov esi, [rbx+HS_FLEN]
        sub esi, eax
        jb .ret0p               ; (more than we ever sent)
        lea esi, [rbx+rsi+HS_FL]
        xchg eax, ecx
        rep movsb
        pop rbx
        xor esi, esi
        jmp .none
.recs:  mov ecx, P80_LEN        ; port 80: so many responses, the first of them possibly
        mov esi, eax            ; not from its start
        add eax, ecx
        dec eax
        xor edx, edx
        div ecx
        push rax
        imul eax, ecx
        sub eax, esi
        xchg eax, esi           ; esi = how much of the first one the client has
        pop rcx
        jrcxz .none
.again: cmp edi, OB + OBMAX - P80_LEN
        ja .none                ; (as many as there is room for)
        call respond
        loop .again
.none:  add esi, OB
        mov ecx, edi
        sub ecx, esi
        jb .ret0
        mov al, 0x19            ; (after our FIN: that again too)
        test byte [rbp+C_FLG], F_CLOSED
        jnz .rs
        mov al, 0x18
        jrcxz .ret0
.rs:    mov edx, [rbx+P_ACK]
        jmp tcp_send
.ret0p: pop rbx
.ret0:  ret
.resetp: pop rbx
.reset: mov al, 4               ; we can't go on with this connection: say so and forget it
        mov edx, [rbp+C_SND]
        xor ecx, ecx
        xor edi, edi
        call tcp_seg
        jmp .free
