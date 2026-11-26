; start.asm: where the image is entered, up to long mode and memory that is ours. `start`
; goes on in setup.asm, behind the SHA-256 constants that os.asm makes in between. A part
; of os.asm, which includes it.
; ----------------------------------------------------------------------------
start:                          ; Entered in 32-bit protected mode by whoever loaded us where
        cli                     ; our header says (boot.asm, GRUB's or QEMU's multiboot), with
        cld                     ; ebx = what a multiboot loader tells its kernel: the memory
        lidt [GDT]              ; map is what we need of it. Nothing else is assumed: no
        mov edi, BSSN           ; interrupt handlers (a table of them of length nothing: see
        mov ecx, (TABV - BSSN) / 4 ; `GDT`), our own page tables, segments and stack, and
        xor eax, eax            ; memory we zero ourselves: first all that is ours below the
        rep stosd               ; table space, and the DELTA bytes between 1 MiB and the
%ifndef WXOPEN                  ; image, which share a page with its first code and are
        mov edi, 0x100000       ; whatever the loader left there. The top table and the
        mov cx, DELTA           ; next one have one entry each for now (the rest is filled
        rep stosb               ; in from long mode), and the first page directory maps
%endif                          ; the first 16 MiB as they are
        mov dword [PML4], PDPT0 + 3
        mov dword [PDPT0], PDT + 3
        mov dword [PDPT0+DEVG*8], PDDEV + 3
        mov byte [PDPT0+DEVG*8+7], 0x80 ; (the card's registers: not to be executed)
        ; Who may do what. Only our code is executed, and it is not written (CR0.WP, once
        ; all is set up); nor is the site. Everything else is data: written, and never
        ; executed. So nothing a packet can put into memory can be run, and nothing that
        ; runs can be changed. The first 2 MiB are in pages of 4 KiB for that: low memory
        ; (data, but for the page where the other processors start), then the image: the
        ; pages with code, and behind them what is only read, which begins with a page
        ; (`codend`): no constant, no key, no certificate and no byte of the site lies in
        ; a page that can be executed.
        mov dword [PDT], PT0 + 3
        mov edi, PT0
        xor ecx, ecx
.pg:    mov eax, ecx
        shl eax, 12
        mov al, 3               ; present, to be written,
        mov edx, 0x80000000     ; not to be executed
        cmp ecx, TRAMP >> 12
        je .x
        test ch, ch
        jz .put
        mov al, 1               ; the image: not to be written,
        cmp ecx, CODEPG
        jae .put                ; and behind its code not to be executed
.x:     mov al, 1
        xor edx, edx
.put:   stosd
        xchg eax, edx
        stosd
        inc ecx
        cmp ch, 2
        jb .pg
        mov edi, PDT + 8        ; From 2 MiB up, pages of 2 MiB: more of the image if it is
        mov eax, 0x200081       ; long (only read), then, from BSS on, data; none of it to be
.low:   cmp eax, BSSN           ; executed
        jb .ro
        or al, 2
.ro:    stosd
        mov byte [edi+3], 0x80
        scasd
        add eax, 0x200000
        cmp eax, TABV
        jb .low
        mov eax, cr4
        or eax, 0x220           ; PAE (long mode's kind of paging); the SSE registers may be used
        mov cr4, eax
        mov eax, PML4
        mov cr3, eax
        mov ecx, 0xC0000080
        rdmsr
        or ah, 9                ; long mode, once paging is on; and pages can be barred from
        wrmsr                   ; execution
        mov eax, cr0
        or eax, 0x80000000
        mov cr0, eax
        lgdt [GDTR]
        jmp 8:.long
BITS 64
.long:  mov esp, STACK
        push 16
        pop rax
        mov ds, eax
        mov es, eax
        mov ss, eax
        mov ebx, ebx            ; (the upper halves are not ours to rely on after the switch)
        mov edi, PDT + (TABV >> 21) * 8
        ; The table space: every 2 MiB of RAM from 16 MiB up that the memory map calls
        ; available, one after the other (rdi = the next page directory entry).
        xor ecx, ecx
        test byte [rbx], 0x40   ; (no memory map: no tables)
        jz .mapped
        mov ecx, [rbx+44]
        mov ebx, [rbx+48]
        add ecx, ebx            ; its end
.ent:   cmp ebx, ecx
        jae .mapped
        cmp byte [rbx+20], 1    ; RAM that is ours to use: from rax up to r8
        jne .nent
        mov rax, [rbx+4]
        mov r8, [rbx+12]
        add r8, rax
        mov edx, TABV
        cmp rax, rdx
        jae .piece
        mov rax, rdx
.piece: add rax, 0x1FFFFF       ; in whole pages, not to be executed
        and rax, -0x200000
        and r8, -0x200000
        mov al, 0x83
        bts rax, 63
        bts r8, 63
.page:  cmp rax, r8
        jae .nent
        cmp edi, PDT_END
        jae .nent
        stosq
        add rax, 0x200000
        jmp .page
.nent:  mov eax, [rbx]          ; (an entry says how long it is, after that length)
        lea ebx, [rbx+rax+4]
        jmp .ent
.mapped:
        mov ebx, edi
        mov edi, PDPT0          ; the page directories, one for each GiB
        mov eax, PDT + 3
        mov ecx, (PDT_END - PDT) >> 12
.gib:   stosq
        add eax, 0x1000
        loop .gib
        sub ebx, PDT + (TABV >> 21) * 8
        shl rbx, 18             ; rbx = the size of the table space
        mov rcx, rbx
        shr rcx, 3
        xor eax, eax
        mov edi, TABV
        rep stosq               ; which starts as zero too
        mov rax, rbx            ; n, for the handshake buffers and the early segments: what
        shr rax, 17             ; takes up 1/32 and 1/64 of it, or the power of two below
        bsr rcx, rax
        cmp cl, 15              ; (C_HS is a word)
        jbe .hn
        mov cl, 15
.hn:    xor eax, eax
        inc eax
        shl eax, cl
        lea edx, [rax-1]
        mov [HSMASK], edx
        mov edx, eax
        shl edx, HS_SHIFT
        add edx, HSP
        mov [OOBASE], edx
        lea ecx, [rax*4-1]      ; 4 n SYNs that may be answered again: 128 bytes each, and
        mov [TMMASK], ecx       ; a dword for when
        shl eax, 11
        add eax, edx
        mov [TMF], eax
        inc ecx
        shl ecx, 7
        add eax, ecx
        mov [TMT], eax
        shr ecx, 5
        add eax, ecx
        mov [RBASE], eax        ; for each processor a ring of frames (n frames, and 2 KiB in
        mov [MYRING], eax       ; front for how far it is) and behind it a queue of 4 n
        shl ecx, 4              ; connections that wait for an ack (64 bytes each: `tarm`)
        lea edx, [rcx*8+2048]
        add ecx, edx
        add edx, eax
        mov [TQB], edx
        mov [RSTEP], ecx
        shl ecx, 2              ; (MAXCPU of them)
        add eax, ecx            ; rax = where the tables start
        lea rbx, [rbx+TABV]
        sub rbx, rax            ; what they have:
        mov edi, TT
        mov [rdi], rax
        mov rax, rbx            ; for TLS a share of that memory,
        shr rax, TSHARE + 11    ; in buckets (of BUCKET * TSLOT = 2048 bytes)
%ifdef CAP                      ; (make CAP=n: no more than n slots in each table, to test full ones)
        cmp rax, CAP / BUCKET
        jbe .tc
        mov eax, CAP / BUCKET
.tc:
%endif
        mov [rdi+8], eax
        shl rax, 11
        sub rbx, rax            ; and for port 80 the rest
        add rax, [rdi]
        mov [rdi+16], rax
        xchg rax, rbx
        xor edx, edx
        mov ecx, BUCKET * PSLOT
        div rcx
%ifdef CAP
        cmp rax, CAP / BUCKET
        jbe .pc
        mov eax, CAP / BUCKET
.pc:
%endif
        mov [rdi+24], eax
        fninit
