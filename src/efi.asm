; efi.asm - what UEFI firmware needs to start os.bin from the same disk: an application
; (PE32+, its headers written out here: nasm -f bin) that tools/mkdisk.py puts into the
; disk's partition as \EFI\BOOT\BOOTX64.EFI, where firmware looks for one, beside os.bin.
;
; It leaves the image the machine a BIOS would have left it, so nothing in os.bin knows
; of it. With the firmware's help: a page below 1 MiB that is ours (code may lie in it),
; memory below 4 GiB for the image and behind it for the firmware's memory map, the file
; os.bin read into that, the memory map, and the firmware's leave (ExitBootServices: from
; there on the machine is ours, and all the firmware had is memory). Then alone: what of
; the map is free is written into our page as a multiboot loader's memory map, the ranges
; that touch as one (os.asm reads the ranges that are RAM for it to use and no others),
; and the rest of `low` is copied behind it. `low` runs there in 32-bit code: it turns
; paging off, which ends long mode, and only then copies the image to where its header
; says: that place is whatever the firmware had there, its page tables perhaps, and from
; `low` on nothing of the firmware's is used (segments, code, the map: all in our page).
; Then the image is entered as boot.asm enters it.
;
; The firmware must not insist on a signature (Secure Boot: off), and a failure is not
; told to anybody: we return to the firmware with what went wrong.

MMAX    equ 128                 ; ranges of memory at most (they and `low` fit in one page)

BITS 64
default rel
        org 0
        db 'MZ'
        times 0x3C - ($ - $$) db 0
        dd pe
pe:     db 'PE', 0, 0
        dw 0x8664, 2            ; x86-64, two sections
        dd 0, 0, 0
        dw opte - opt, 0x0206   ; (it can be run; nothing of it is left out)
opt:    dw 0x20B                ; PE32+
        db 0, 0
        dd TEXTF, 0x200, 0
        dd 0x1000 + efi - text  ; where it is entered,
        dd 0x1000
        dq 0                    ; wherever it is loaded (no address in it is absolute)
        dd 0x1000, 0x200        ; a section begins at a page in memory, at a sector in the file
        dw 0, 0, 0, 0, 0, 0
        dd 0
        dd 0x3000, 0x200        ; all of it in memory; the headers
        dd 0
        dw 10, 0                ; an EFI application
        dq 0, 0, 0, 0
        dd 0, 16
        times 5 dq 0
        dd 0x2000, 12           ; what is to be changed where it is loaded: nothing, said in
        times 10 dq 0           ; a section (there is firmware that wants to be told)
opte:   db '.text', 0, 0, 0
        dd texte - text, 0x1000, TEXTF, 0x200
        dd 0, 0, 0, 0x60000020  ; code: executed and read (what we write is on the stack)
        db '.reloc', 0, 0
        dd 12, 0x2000, 0x200, 0x200 + TEXTF
        dd 0, 0, 0, 0x42000040
        times 0x200 - ($ - $$) db 0

text:
dest:   dd 0                    ; What tools/mkdisk.py fills in: where the image goes (its
entry:  dd 0                    ; header's load address), where it is entered, and its
len:    dd 0                    ; length in bytes
; rcx = our handle, rdx = the system table; and the firmware's way of calling: arguments in
; rcx, rdx, r8, r9, then on the stack above 32 bytes that are the callee's; rbx, rbp, rsi
; and rdi are kept. On the stack: +0x28 what was last asked for, +0x30 where the image is
; read to, +0x38 a length, +0x40.. what the memory map comes with, +0x58 our page
efi:    push rbx
        push rbp
        push rsi
        push rdi
        sub rsp, 0x68
        mov rbp, rcx
        mov rbx, [rdx+0x60]     ; the boot services
        lea rdx, [gimage]
        lea r8, [rsp+0x28]
        call [rbx+0x98]         ; HandleProtocol: what we were loaded as,
        test rax, rax
        jnz .out
        mov rcx, [rsp+0x28]
        mov rcx, [rcx+0x18]     ; the device it was from,
        lea rdx, [gfs]
        lea r8, [rsp+0x28]
        call [rbx+0x98]         ; and that one's file system:
        test rax, rax
        jnz .out
        mov rcx, [rsp+0x28]
        lea rdx, [rsp+0x28]
        call [rcx+8]            ; OpenVolume: its first directory,
        test rax, rax
        jnz .out
        mov rcx, [rsp+0x28]
        lea rdx, [rsp+0x28]
        lea r8, [name]
        push 1                  ; (to be read)
        pop r9
        mov [rsp+0x20], rax
        call [rcx+8]            ; Open: os.bin in it
        test rax, rax
        jnz .out
        push 1                  ; AllocatePages: at or below an address, for code, one page:
        pop rcx                 ; ours below 1 MiB
        mov edx, ecx
        mov r8d, ecx
        lea r9, [rsp+0x58]
        mov qword [r9], 0xFFFFF
        call [rbx+0x28]
        test rax, rax
        jnz .out
        mov esi, [len]
        push 1                  ; and for data, below 4 GiB (`low` copies from there): the
        pop rcx                 ; image's pages and 64 KiB for the memory map
        push 2
        pop rdx
        lea r8d, [rsi+0x10FFF]
        shr r8d, 12
        lea r9, [rsp+0x30]
        dec eax
        mov [r9], rax
        call [rbx+0x28]
        test rax, rax
        jnz .out
        mov rcx, [rsp+0x28]
        lea rdx, [rsp+0x38]
        mov [rdx], rsi
        mov r8, [rsp+0x30]
        call [rcx+0x20]         ; Read: all of the image
        test rax, rax
        jnz .out
        cmp [rsp+0x38], rsi
        jne .short
        add esi, 0xFFF
        and esi, -0x1000
        add rsi, [rsp+0x30]     ; rsi = where the memory map goes
.map:   lea rcx, [rsp+0x38]
        mov qword [rcx], 0x10000
        mov rdx, rsi
        lea r8, [rsp+0x40]      ; (its key: which map it is)
        lea r9, [rsp+0x48]      ; (how long one range's entry is)
        lea rax, [rsp+0x50]
        mov [rsp+0x20], rax
        call [rbx+0x38]         ; GetMemoryMap
        test rax, rax
        jnz .out
        mov rcx, rbp
        mov rdx, [rsp+0x40]
        call [rbx+0xE8]         ; ExitBootServices (the map may have changed under the
        test rax, rax           ; firmware's hands: then it wants to see the new one)
        jnz .map
        cli
        cld
        mov rdx, [rsp+0x38]
        add rdx, rsi            ; the map's end
        mov ebx, [rsp+0x58]     ; Our page: first the ranges, as boot.asm leaves them (20 |
        mov edi, ebx            ; base | length | 1). Free is what was free, what was the
        lea r9d, [rbx+24*MMAX]  ; firmware's until it left, and what was ours (types 1 to
        or r8, -1               ; 4 and 7). r8 = where the last range ended
.range: cmp rsi, rdx
        jae .last
        mov ecx, [rsi]
        cmp ecx, 7
        ja .next
        mov eax, 0x9E
        bt eax, ecx
        jnc .next
        mov rax, [rsi+8]
        mov rcx, [rsi+24]       ; (in pages)
        shl rcx, 12
        cmp rax, r8
        jne .new
        add [rdi-12], rcx
        jmp .end
.new:   cmp edi, r9d
        jae .next
        mov dword [rdi], 20
        mov [rdi+4], rax
        mov [rdi+12], rcx
        mov dword [rdi+20], 1
        add edi, 24
.end:   lea r8, [rax+rcx]
.next:  add rsi, [rsp+0x48]
        jmp .range
.last:  sub edi, ebx
        mov dword [r9], 0x40    ; behind them the multiboot information: there is a memory
        mov [r9+44], edi        ; map, so long, there;
        mov [r9+48], ebx
        lea rsi, [low]          ; and `low`, with the segments it runs with
        lea edi, [r9+64]
        mov edx, edi
        push lowe - low
        pop rcx
        rep movsb
        lea rax, [rdx+gdt-low]
        mov [rdx+gdtr-low+2], rax
        lgdt [rdx+gdtr-low]
        mov esi, [rsp+0x30]     ; what it is to copy, where to, how much; where to go then,
        mov edi, [dest]         ; and with what in ebx
        mov ecx, [len]
        mov ebp, [entry]
        mov ebx, r9d
        push 8
        push rdx
        retfq
.short: mov rax, 0x8000000000000001 ; (a load error)
.out:   add rsp, 0x68
        pop rdi
        pop rsi
        pop rbp
        pop rbx
        ret

BITS 32
low:    mov eax, 16             ; Flat segments, as a multiboot loader leaves them. Then
        mov ds, eax             ; the processor as a BIOS leaves it: no paging (so no long
        mov es, eax             ; mode: that first, the rest can't be changed in it), no
        mov ss, eax             ; extensions switched on, protected mode and nothing else
        mov fs, eax             ; (what is not written is still written: os.asm relies on
        mov gs, eax             ; that until it has set up)
        mov eax, cr0
        btr eax, 31
        mov cr0, eax
        xor eax, eax
        mov cr4, eax
        mov al, 0x11
        mov cr0, eax
        cmp esi, edi            ; The image, to its place. (From its end if it is copied
        jae .up                 ; upwards: the two may share memory.)
        lea esi, [esi+ecx-1]
        lea edi, [edi+ecx-1]
        std
.up:    rep movsb
        cld
        mov ecx, 0xC0000080     ; (long mode is not asked for any more, nor pages barred
        rdmsr                   ; from execution: os.asm asks)
        and eax, ~0x901
        wrmsr
        mov eax, 0x2BADB002     ; enter it the way a multiboot loader does
        jmp ebp
gdt:    dq 0
        dq 0x00CF9A000000FFFF   ; 8: code, 4 GiB
        dq 0x00CF92000000FFFF   ; 16: data, 4 GiB
gdtr:   dw 23
        dq 0
lowe:
%if 24 * MMAX + 64 + lowe - low > 4096
%error "the memory map and `low` are more than a page"
%endif

gimage: dd 0x5B1B31A1           ; the names of the two things asked for: a loaded image,
        dw 0x9562, 0x11D2
        db 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B
gfs:    dd 0x964E5B22           ; a file system
        dw 0x6459, 0x11D2
        db 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B
name:   dw 'o', 's', '.', 'b', 'i', 'n', 0
texte:
        align 512, db 0
TEXTF   equ $ - text
        dd 0, 12                ; (.reloc: a list of nothing)
        dw 0, 0
        align 512, db 0
