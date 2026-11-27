; poll.asm: the polling loops of the first processor and the others, the rings frames reach
; the others through, and frames to the card. A part of os.asm, which includes it.
poll:
%ifdef LIFE                     ; development builds (make LIFE=n): after n minutes the
        call clock              ; machine is reset, whatever happens: a test server then
        sub eax, [BORN]         ; boots what its disk boots by default, also when the network
        cmp eax, LIFE * 60 * 2048 ; side of a new image turns out not to work
        ja reset
%endif
        cmp dword [CPUN], 0
        jne .ring
        call drain
%ifndef OURIP
        call dhask              ; (if it is time: for an address, or to keep ours)
%endif
.ring:  call ring1              ; then one frame of our own, if there is one
        jnz poll
        call txkick             ; none: time to tell the device what we have queued for it,
        call tidle              ; to see who has waited too long for an ack,
        call tqrun
        cmp dword [POOLN], 0    ; and to get on with the next signatures if there are none
        jne .idle
        call stock
        jmp poll
.idle:  count 9                 ; (a turn with nothing to do)
        pause
        jmp poll

; ring1: the next frame in this processor's ring goes through `tcp`; ZF if there is none.
; (Clobbers everything.)
ring1:  mov ebx, [MYRING]
        mov eax, [rbx+64]
        cmp eax, [rbx]
        je .none
        and eax, [HSMASK]
        inc eax
        shl eax, 11
        lea esi, [rbx+rax]
        lodsd
        mov ecx, eax
        mov [RXLEN], ecx
        xor edi, edi            ; FR
        rep movsb
        inc dword [rbx+64]
        test byte [rbx+64], 31  ; (if frames keep coming, the device is told of ours every
        jnz .go                 ; 32 of them)
        call txkick
.go:    call tcpd
        or al, 1
.none:  ret

; drain (the first processor's): everything the device has goes into our own rings, each
; frame into the ring of the processor whose connection it is. That takes a few hundred
; cycles a frame, and it is done before every frame handled and at intervals during what
; takes long (`bdrain`), so the device's ring (256 on the server) only has to hold what
; comes in some tens of microseconds, and what we can't keep up with waits in ours (n
; frames each, see TABV: 16,384 in 4 GiB) instead of being lost: with handshakes to make
; that is what half a second brings. A connection is one processor's: which, the hash of
; its addresses and ports says (the bits that also pick the place of an early segment:
; those are then one processor's too). Clobbers rax, rcx, rdx, rbx, rsi, rdi, xmm0.
drain:  mov esi, [Q0+8]         ; used ring: anything new?
        mov eax, [Q0+Q_SEEN]
        cmp ax, [rsi+2]
        je ring1.none           ; (nothing: the `ret` in front of us is the near one)
        inc dword [Q0+Q_SEEN]
        and eax, [Q0+12]
        mov edx, [rsi+4+rax*8]  ; buffer id
        mov ecx, [rsi+8+rax*8]  ; bytes written, header included
        mov esi, edx
        and esi, [Q0+12]        ; (id and length are the device's: keep both inside our buffers)
        shl esi, 11
        add esi, RXB + 12
        sub ecx, 12
        and ecx, 2047
        xor eax, eax
        cmp [abs NCPUM], eax
        je .put
%ifndef OURIP                   ; (UDP is the first processor's: it may be a DHCP server's
        cmp word [rsi+12], 0x0008 ; answer, and the one who asks is the one who knows what
        jne .hash               ; was asked, and the only one to change what is known:
        cmp byte [rsi+23], 17   ; `dhcp`)
        je .put
.hash:
%endif
        push rsi
        push rcx
        call prf
        pop rcx
        pop rsi
        pextrd eax, xmm0, 3
        and eax, [abs NCPUM]
.put:   imul eax, [RSTEP]
        add eax, [RBASE]        ; that processor's ring: how many frames have been written,
        mov ebx, eax            ; at +64 how many read, then the frames (2 KiB each, length
        mov edi, [rbx]          ; first)
        mov eax, edi
        sub eax, [rbx+64]
        cmp eax, [HSMASK]
        ja .lost                ; (full: the frame is lost)
        cmp ecx, 2044
        ja .give                ; (and so is one that would not fit its place there)
        and edi, [HSMASK]
        inc edi
        shl edi, 11
        add edi, ebx
        mov eax, ecx
        stosd
        rep movsb
        inc dword [rbx]
.give:  mov esi, [Q0+4]         ; give the buffer back
        movzx eax, word [rsi+2]
        and eax, [Q0+12]
        mov [rsi+4+rax*2], dx
        inc word [rsi+2]
        mov esi, [Q0+8]
        test byte [rsi], 1      ; the device says when it doesn't need to be told
        jnz drain
        mov rdx, [Q0+Q_NOTE]
        mov word [rdx], 0
        jmp drain
.lost:  count 2
        jmp .give

; bdrain: the same, from the middle of long work, on whichever processor: keeps the eight
; old registers
bdrain: cmp dword [CPUN], 0
        jne .no
        pushad
        call drain
        popad
.no:    ret

; apstart: where another processor goes on, in long mode, from where it started (`tramp`,
; at the end of the code): it lives off the frames the first processor puts in its ring.
apstart: mov esp, STACK
        push 16
        pop rax
        mov ds, eax
        mov es, eax
        mov ss, eax
        lidt [GDT]              ; (no interrupt handlers here either: see `GDT`)
        mov eax, [CPUN]
        imul eax, [RSTEP]
        add [TQB], eax          ; (its own queue of waiting connections, and its own ring)
        add eax, [RBASE]
        mov [MYRING], eax
.w:     pause                   ; Until the first processor has counted us. Frames go to a
        mov eax, [abs NCPUM]    ; power of two of us: one that gets none (the third of
        test eax, eax           ; three; one that came after the count) has nothing to do,
        jz .w                   ; and must not go through the motions either: its turn at
        cmp [CPUN], eax         ; the SYNs of late (`tidle`) would be at another's
        ja .rest
        call drbg_seed          ; APs copied the boot CPU's BSS; mix in fresh per-CPU entropy
%ifdef WXTEST
%if WXTEST = 7                  ; (the same on a processor that was started up: its table is
        WXGATE poll             ; at address 0 whatever loaded us)
%endif
%endif
        jmp poll
.rest:  hlt
        jmp .rest

%ifdef DEBUG
tcpd:   rdtsc                   ; (`tcp`, with the cycles spent on frames, and how many frames)
        push rax
        call tcp
        rdtsc
        pop rdx
        sub eax, edx
        add [DBG+24], eax
        adc dword [DBG+28], 0
        inc dword [DBG+32]
        ret
%endif

%ifdef LIFE
; reset: the machine starts over (development builds only: LIFE)
reset:  mov al, 0xFE
        out 0x64, al            ; keyboard controller: pulse the reset line
        int3                    ; (and if that does nothing: a fault, which nobody handles)
%endif

; pcird: eax = PCI configuration dword at register eax of the device at ebx (dx = 0xCFC after)
pcird:  and al, 0xFC
        add eax, ebx
        mov dx, 0xCF8
        out dx, eax
        mov dl, 0xFC
        in eax, dx
        ret

; txbuf: ebx = where to build the next frame to send. Each frame gets its own buffer, the next
; of N in a circle; if the device still has all N, wait for it.
txbuf:  pushad
.lock:  lock bts dword [abs TXLOCK], 0 ; (one processor at a time, until `txgo`)
        jnc .mine
        call bdrain             ; (what comes in while we wait must not wait for us)
        pause
        jmp .lock
.mine:  mov ebx, [Q1+4]         ; available ring
        mov esi, [Q1+8]         ; used ring
        movzx eax, word [rbx+2]
.full:  mov edx, eax
        sub dx, [rsi+2]
        cmp dx, [Q1+12]
        jbe .room
        call txkick.now         ; (whoever queued them: another processor may be waiting for us)
        call bdrain
        jmp .full
.room:  and eax, [Q1+12]        ; buffer = descriptor = ring position
        shl eax, 11
        add eax, TXB + 12
        mov [rsp+24], rax
        popad
        ret

; txgo: queue the frame of ecx bytes at ebx: built where txbuf said, or in a buffer of the
; caller's own (`txbig`), after txbuf has made the ring ours. It goes out with txkick.
txgo:   pushad
        mov edx, [Q1+4]
        movzx eax, word [rdx+2]
        and eax, [Q1+12]
        mov [rdx+4+rax*2], ax
        shl eax, 4
        add eax, [Q1]
        sub ebx, 12             ; (in front of a frame, 12 bytes for the device: all zero, or
        mov [rax], rbx          ; what `tcp_big` says there)
        add ecx, 12
        mov [rax+8], ecx
        inc word [rdx+2]
        inc qword [abs TXCNT]
        mov byte [TXK], 1
        mov byte [abs TXLOCK], 0
        popad
        ret

; txbig: ebx = where this processor may build a frame of up to 64 KiB (for `tcp_big`): the
; next of its BIGS buffers, in a circle, once the device has sent what the buffer last held.
; That it has when it has sent as many frames as had been queued by the time the buffer
; after this one was asked for (BIGQ has that count; the device sends in the order of the
; ring). Until then: wait, and let what comes in go on to the rings. (Clobbers eax, edx,
; esi, edi.)
txbig:  mov eax, [BIGN]
        inc dword [BIGN]
        lea rsi, [BIGQ]
        mov rdx, [abs TXCNT]
        lea edi, [rax-1]
        and edi, BIGS - 1
        mov [rsi+rdi*8], rdx    ; (the buffer before this one: its frame is queued by now)
        and eax, BIGS - 1
.wait:  mov edx, [Q1+8]
        movzx edi, word [rdx+2] ; How many frames the device has sent (a word of that count;
        mov rdx, [abs TXCNT]    ; read before the count of those queued, of which it is then
        neg edi                 ; never ahead):
        add edi, edx
        movzx edi, di           ; so many it still has,
        sub rdx, [rsi+rax*8]    ; and so many were queued after this buffer's
        cmp rdx, rdi
        jae .free
        call txkick.now
        call bdrain
        pause
        jmp .wait
.free:  mov ebx, [CPUN]
        shl ebx, BIGSH
        add ebx, eax
        shl ebx, 16
        add ebx, BIGB + 32      ; (12 bytes for the device, and the 20 that an IPv6 header
        ret                     ; is longer than the one a frame is laid out for: `tcp_seg`)

; txkick: tell the device that there are frames to send, if there are some it has not been
; told about and it wants to be told. Telling costs far more than anything else we do for a
; frame (it leaves the virtual machine), so the polling loop does it when it has handled
; all that came in, not for every frame.
txkick: push rax
        btr dword [TXK], 0
        jnc .no
        mov eax, [Q1+8]
        test byte [rax], 1
        jnz .no
.tell:  mov rax, [Q1+Q_NOTE]
        mov word [rax], 1       ; notify queue 1
.no:    pop rax
        ret
.now:   push rax
        jmp .tell

; ethhdr: at edi (which moves on) the start of a frame to the sender of the one in FR: to its
; address, from ours (clobbers esi)
ethhdr: push 6
        pop rsi                 ; FR + 6
        movsd
        movsw
        mov esi, MAC
        movsd
        movsw
        ret
