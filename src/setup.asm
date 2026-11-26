; setup.asm: `start`, behind the SHA-256 constants: what every key schedule begins with, the
; card, the other processors. A part of os.asm, which includes it.
        call ecinit             ; what the curves need (fields, constants, tables)
        mov ebp, SLOTS + 128    ; and what every key schedule starts with: SHA256(""), the
        xor ecx, ecx            ; early secret of no PSK, and what the handshake secret is
        lea edi, [rbp+S_EH]     ; derived from
        call sha256
        lea ebx, [rbp+S_Z]
        mov esi, ebx
        mov cl, 32
        lea edi, [rbp+S_ES]
        call hmac
        mov ebx, edi
        mov esi, L_DER
        lea edx, [rbp+S_EH]
        lea edi, [rbp+S_D1]
        call expand

        ; virtio-net, modern interface (virtio 1.0; what a cloud's 1AF4:1041 speaks, and a
        ; transitional 1AF4:1000 too): the registers are memory, found through the device's
        ; PCI capabilities, wherever the BIOS put them (each kind of structure is mapped
        ; into a place of its own in our address space). Two queues (0 receive, 1 transmit);
        ; descriptor i always points at buffer i.
        mov ebx, 0x80000000     ; PCI configuration address: bus 0, device 0, function 0
.pci:   xor eax, eax
        call pcird
        cmp ax, 0x1AF4
        jne .next
        shr eax, 16
        cmp ax, 0x1041
        je .dev
        cmp ax, 0x1000
        je .dev
.next:  add ebx, 0x100          ; next function, device, bus (the card sits behind a bridge)
        jmp .pci
.dev:   push 4
        pop rax
        call pcird
        or al, 7                ; command: I/O, memory, bus master
        out dx, ax
        push 0x34
        pop rax
        call pcird
        xchg eax, esi           ; capability list
.cap:   and esi, 0xFC
        jz .caps
        mov eax, esi
        call pcird              ; id | next | length | type (1 common, 2 notify, 4 device)
        mov ecx, eax
        cmp al, 9               ; vendor-specific: a virtio structure
        jne .nxt
        shr eax, 24
        cmp al, 4
        ja .nxt
        lea rbp, [VCAP+rax*8]
        cmp qword [rbp], 0      ; the first of each kind counts
        jne .nxt
        xchg eax, edi           ; edi = the kind
        lea eax, [rsi+4]
        call pcird
        movzx eax, al           ; which BAR
        lea r8d, [rax*4+0x10]
        mov eax, r8d
        call pcird
        mov r9d, eax
        and r9d, -16            ; r9 = where it is,
        test al, 4
        jz .bar
        lea eax, [r8+4]         ; with an upper half in the next register if it is a 64-bit one
        call pcird
        shl rax, 32
        or r9, rax
.bar:   lea eax, [rsi+8]
        call pcird              ; and the structure's offset inside it
        add r9, rax
        shl edi, 4              ; map the 2 MiB page it is in, and the next
        mov rax, r9
        and rax, -(1 << 21)
        mov al, 0x9B            ; (present, writable, 2 MiB, not cached)
        mov [PDDEV+rdi], rax
        add rax, 1 << 21
        mov [PDDEV+rdi+8], rax
        and r9d, (1 << 21) - 1
        shl edi, 18
        add r9, rdi
        mov eax, DEVG
        shl rax, 30
        add rax, r9
        mov [rbp], rax
        lea eax, [rsi+16]
        call pcird              ; (notify: the multiplier for queue_notify_off)
        mov [rbp+VMUL-VCAP], eax
.nxt:   movzx esi, ch
        jmp .cap
.caps:  mov rbp, [VCAP+8]       ; common configuration
        mov byte [rbp+20], 0    ; status 0: reset
        mov byte [rbp+20], 3    ; ACKNOWLEDGE | DRIVER
        xor eax, eax
        inc eax
        mov [rbp+8], eax        ; features, word 1: VERSION_1 (bit 32), nothing else:
        mov [rbp+12], eax       ; frames behind a 12-byte header
        dec eax
        mov [rbp+8], eax        ; Word 0: that the card sums what we send (CSUM, bit 0) and
        mov [rbp], eax          ; cuts a frame of up to 64 KiB into segments (HOST_TSO4, bit
%ifndef NOTSO                   ; 11), if it offers both: then a response goes many records
        mov eax, [rbp+4]        ; to a frame (`sendrun`). (make NOTSO=1: never.)
%ifdef OURIP6                   ; (And the same over IPv6, HOST_TSO6, bit 12, if it offers
        and eax, 0x1801         ; that: `cuts` says which of the two there is.)
        test al, 1
        jnz .tso
%else
        and eax, 0x801
        cmp eax, 0x801
        je .tso
%endif
        xor eax, eax
.tso:
%endif
        mov [rbp+12], eax
        mov [TSO], eax
        mov byte [rbp+20], 11   ; FEATURES_OK
        mov rsi, [VCAP+32]      ; device configuration: the MAC comes first
        mov edi, MAC
        movsd
        movsw
        xor ebx, ebx            ; queue
.q:     mov [rbp+22], bx        ; select it
        movzx ecx, word [rbp+24] ; its size N (a power of two)
        cmp ecx, 1024
        jbe .n
        mov ecx, 1024           ; (what our ring area holds)
        mov [rbp+24], cx
.n:     mov esi, ebx
        shl esi, 5
        add esi, Q0             ; our notes on this queue
        mov edi, ebx
        shl edi, 16
        add edi, VQ
        mov [rsi], edi          ; descriptors: 16 N bytes
        mov [rbp+32], edi
        lea eax, [rcx-1]
        mov [rsi+12], eax
        mov eax, ecx
        shl eax, 4
        add eax, edi
        mov [rsi+4], eax        ; available ring: flags, idx, N entries
        mov [rbp+40], eax
        mov byte [rax], 1       ; (its flags: no interrupts. We look for ourselves, and
                                ; nobody would take them)
        lea eax, [rax+rcx*2+6+4095]
        and eax, -4096
        mov [rsi+8], eax        ; used ring: flags, idx, N x (id, length)
        mov [rbp+48], eax
        push rcx
        imul eax, ebx, TXB - RXB
        add eax, RXB
        mov edx, ebx
        xor dl, 1
        shl edx, 1              ; receive buffers are for the device to write (flag 2)
.desc:  mov [rdi], eax
        mov dword [rdi+8], 2048
        mov [rdi+12], edx
        add eax, 2048
        add edi, 16
        loop .desc
        pop rcx
        test ebx, ebx
        jnz .en
        mov edi, [rsi+4]        ; receive: hand all N buffers to the device
        mov [rdi+2], cx
        xor eax, eax
.av:    mov [rdi+4+rax*2], ax
        inc eax
        cmp eax, ecx
        jb .av
.en:    movzx eax, word [rbp+30] ; where to notify the device about this queue
        imul eax, [VMUL+16]
        add rax, [VCAP+16]
        mov [rsi+Q_NOTE], rax
        mov word [rbp+28], 1    ; enable
        inc ebx
        cmp bl, 2
        jb .q
        mov byte [rbp+20], 15   ; DRIVER_OK
        mov rdx, [Q0+Q_NOTE]
        mov word [rdx], 0       ; notify queue 0: there are buffers

        mov edi, HKS            ; the round keys for `prf`
        push 22
        pop rcx
        call rand

        mov ecx, 1 << 26        ; Calibrate the clock against timer 2 (1,193,182 Hz):
        mov bl, 2               ; 9,322 ticks are 1/128 s, or 16 of our ticks of 1/2048 s
.cal:   in al, 0x61             ; (two runs, the shorter counts: the host may interrupt one)
        and al, 0xFC
        or al, 1
        out 0x61, al
        mov al, 0xB0
        out 0x43, al
        mov ax, 9322
        out 0x42, al
        mov al, ah
        out 0x42, al
        call tsc
        xchg rsi, rax
.pit:   pause
        in al, 0x61
        mov bh, al
        call tsc
        sub rax, rsi
        cmp rax, rcx
        jae .pnx
        test bh, 0x20
        jz .pit
        cmp eax, 1 << 19
        jb .pnx
        xchg eax, ecx
.pnx:   dec bl
        jnz .cal
        cmp ecx, 1 << 26
        jb .pok
        mov ecx, 1 << 24        ; (no timer: 2^20 cycles a tick, as at 2.1 GHz)
.pok:   xor eax, eax
        push 16
        pop rdx
        div rcx
        mov [TSCM], rax
%ifdef LIFE
        call clock
        mov [BORN], eax
%endif
        ; The other processors, should there be any (up to MAXCPU - 1): each gets page
        ; tables (as ours, but for BSS and page 0) and a copy of BSS as it is now: all the
        ; constants, and nothing yet of what must not be the same on two processors (the
        ; nonces of `stock`: none have been made).
        mov esi, tramp
        mov edi, TRAMP
        push TRAMPLEN
        pop rcx
        rep movsb
%ifndef WXOPEN
        xor eax, eax            ; Behind it, zero: the rest of that page, which can be
        mov cx, TXLOCK + 48 - TRAMP - TRAMPLEN ; executed and is whatever the loader left
        rep stosb               ; there (boot.asm reads the image through it: its last
                                ; piece, site and all), and on to what is shared down
                                ; there, which starts as zero
%endif
        mov rax, cr0            ; From here on, what the page tables say is not written is
        bts eax, 16             ; not written by us either (those were the last such
        mov cr0, rax            ; writes)
%ifdef WXOPEN                   ; (tools/wxtest.sh's control: what the loader left stays)
        mov edi, TXLOCK
        xor eax, eax
        mov cl, 6
        rep stosq
%endif
%ifndef OURIP
        call clock              ; (no address yet: it is time to ask for one, `dhask`)
        mov [rdi+DHT-TXLOCK-48], eax
%endif
        mov ebx, 1
.cpu:   mov r8d, ebx
        shl r8d, 15
        add r8d, APMEM - 0x8000
        lea eax, [r8+0x1003]
        mov [r8], rax           ; top table: one entry, to
        mov esi, PDPT0
        lea edi, [r8+0x1000]
        mov ch, 2
        rep movsq               ; a copy of our second one, whose first GiB is from
        lea eax, [r8+0x2003]
        mov [r8+0x1000], rax
        mov esi, PDT
        mov ch, 2
        rep movsq               ; a copy of our first page directory, whose first 2 MiB
        lea eax, [r8+0x3003]    ; are in pages of 4 KiB,
        mov [r8+0x2000], rax
        mov eax, ebx
        shl eax, 21
        add eax, APBSS - 0x200000 + 0x83
        bts rax, 63
        mov [r8+0x2000+(BSSN>>21)*8], rax ; and whose 2 MiB at BSS are its own
        mov esi, PT0
        mov ch, 2
        rep movsq
        lea eax, [r8+0x4003]
        bts rax, 63
        mov [r8+0x3000], rax    ; (page 0: its own)
        mov esi, BSS
        mov edi, ebx
        shl edi, 21
        add edi, APBSS - 0x200000
        mov ecx, 0x200000 / 8
        rep movsq
        mov [rdi+CPUN-STACK], ebx
        inc ebx
        cmp bl, MAXCPU
        jb .cpu
        mov eax, 0xFEE0009B     ; The local APIC, mapped where the card's structures are:
        mov [abs PDDEV+10*8], rax ; INIT to all the others, then twice "start at TRAMP"
        mov rsi, (DEVG << 30) + (10 << 21) + 0x300
        mov ebx, 0x000C4500
        call .wait
        mov bx, 0x4600 + (TRAMP >> 12)
        call .wait
        call .wait
        mov eax, [abs TRAMP+apcount-tramp] ; So many came. Frames go to a power of two of us.
        cmp eax, MAXCPU - 1
        jbe .came
        push MAXCPU - 1
        pop rax
.came:  inc eax
        bsr ecx, eax
        xor eax, eax
        inc eax
        shl eax, cl
        dec eax
        mov [abs NCPUM], eax
%ifdef WXTEST                   ; (make WXTEST=n, for tools/wxtest.sh: each of these must be
%if WXTEST = 1                  ; the machine's end)
        mov byte [mb], 0        ; code written
%elif WXTEST = 2
        mov eax, STACK - 64     ; data executed
        mov byte [rax], 0xC3
        call rax
%elif WXTEST = 3
        mov byte [SITE + SITE_LEN - 1], 0 ; the site written
%elif WXTEST = 4                ; the site executed: the first byte of it that says "return"
        mov edi, SITE           ; (tools/wxtest.sh sees to it that there is one). A site
        mov ecx, SITE_LEN       ; that could be run would come back from there, and the
        mov al, 0xC3            ; machine would go on.
        repne scasb
        jne poll
        dec edi
        call rdi
%elif WXTEST = 9                ; the same for the last such byte: of a long site, which lies
        mov edi, SITE + SITE_LEN - 1 ; in large pages there
        mov ecx, SITE_LEN
        mov al, 0xC3
        std
        repne scasb
        cld
        jne poll
        inc edi
        call rdi
%elif WXTEST = 10               ; what lies right behind the code executed (`codend`: in these
        call WXRET              ; builds a "return")
%elif WXTEST = 11               ; and what lies in front of it: the byte at 1 MiB, where
        mov eax, 0x100000       ; tools/wxtest.sh has put a "return" before we were loaded.
        call rax                ; (Zeroed, as `start` leaves it, it is "add [rax], al": a
                                ; write to that very page.)
%elif WXTEST = 12               ; what the loader left in the page the other processors
        mov edi, TRAMP + TRAMPLEN ; start in, behind their code: if anything, the machine
        mov ecx, 4096 - TRAMPLEN ; goes on
        xor eax, eax
        repe scasb
        jne poll
        ud2
%elif WXTEST = 5
        mov eax, RXB            ; a packet buffer executed
        mov byte [rax], 0xC3
        call rax
%elif WXTEST = 6                ; a fault, with a handler for it named where the frame in hand
        WXGATE poll             ; lies (as a client's packet could name one)
%endif
%ifdef WXPAD                    ; (make WXPAD=1: 64 bytes more of code, for an image of
        times 64 nop            ; tools/wxtest.sh that would otherwise lie at 1 MiB exactly,
%endif                          ; with nothing in front of it to look at)
%endif
        jmp poll
.wait:  mov [rsi], ebx
        call clock              ; (22 ticks: 10.7 ms)
        mov ecx, eax
.w:     pause
        call clock
        sub eax, ecx
        cmp eax, 22
        jb .w
        ret
