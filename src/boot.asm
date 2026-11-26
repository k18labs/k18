; boot.asm - boot sector: what a BIOS needs to start os.bin from a disk (a cloud server's, or
; `qemu -drive`). The disk image is this sector and behind it a partition with os.bin in
; it (tools/mkdisk.py, which tells us the sector the image begins at; the partition is
; for firmware that is no BIOS: src/efi.asm).
;
; Loads the image to where its multiboot header says (1 MiB and a few bytes: tools/mkdisk.py
; reads that header and tells us), however long it is (it ends with the site it serves), a
; piece of 32 KiB at a time: the BIOS reads a piece into low memory, and we copy it up from real
; mode with segments that reach all of memory (set in a moment of protected mode before
; each copy: the BIOS may have set them back). Then it asks the BIOS for its memory map,
; enters 32-bit protected mode with flat segments, and enters the image where its
; multiboot header says, with the memory map in a multiboot information structure, as
; GRUB would pass it. (os.asm then sets up long mode, its own segments and stack, and
; zeroes its memory, as it does after any other loader.)

LOAD    equ 0x8000              ; where the BIOS reads a piece of the image to
CHUNK   equ 64                  ; sectors a piece: 32 KiB
MMAP    equ 0x6000              ; the memory map: entries of size (20) | base | length | type
MMAX    equ 128                 ;   (as many as fit below the stack)

BITS 16
        org 0x7C00
        cli
        cld
        xor ax, ax
        mov ds, ax
        mov es, ax
        mov ss, ax
        mov sp, 0x7C00
        mov [drive], dl         ; the drive we were booted from
        in al, 0x92
        or al, 2
        out 0x92, al            ; A20, in case it is off
.piece: sti
        mov si, dap
        mov dl, [drive]
        mov ah, 0x42            ; extended read
        int 0x13
        jc $                    ; (nothing to fall back on)
        cli
        xor ax, ax
        mov ds, ax
        lgdt [gdtr]
        mov eax, cr0
        or al, 1
        mov cr0, eax
        mov bx, 16              ; segments without a limit, for the copy
        mov ds, bx
        mov es, bx
        dec ax
        mov cr0, eax
        mov esi, LOAD
        mov edi, [dest]         ; (where the next piece goes)
        mov ecx, CHUNK * 512 / 4
        a32 rep movsd
        xor ax, ax
        mov ds, ax
        mov es, ax
        mov [dest], edi
        add dword [dap+8], CHUNK
        sub dword [left], CHUNK
        ja .piece
        mov di, MMAP + 4        ; int 15h, E820: one range per call, ebx says where we are
        xor ebx, ebx
.e820:  mov eax, 0xE820
        mov edx, 0x534D4150     ; "SMAP"
        mov ecx, 20
        mov [di-4], ecx
        int 0x15
        jc .done                ; (the end, said the other way)
        cmp eax, 0x534D4150     ; (a BIOS that knows this call says "SMAP" back; what one
        jne .done               ; that does not leaves there is no range)
        add di, 24
        cmp di, MMAP + 4 + 24 * MMAX
        jae .done
        test ebx, ebx
        jnz .e820
.done:  sub di, MMAP + 4
        mov [mbi+44], di
        cli
        lgdt [gdtr]
        mov eax, cr0
        or al, 1
        mov cr0, eax
        jmp 8:pm
BITS 32
pm:     mov ax, 16
        mov ds, ax
        mov es, ax
        mov ss, ax
        mov fs, ax
        mov gs, ax
        mov esp, 0x7C00
        mov eax, 0x2BADB002     ; enter it the way a multiboot loader does
        mov ebx, mbi
        jmp [entry]             ; the multiboot header's entry address

drive:  db 0
mbi:    dd 0x40                 ; multiboot information: flags (there is a memory map),
        times 10 dd 0
        dd 0, MMAP              ;   its length and address
gdt:    dq 0
        dq 0x00CF9A000000FFFF   ; 8: code, 4 GiB
        dq 0x00CF92000000FFFF   ; 16: data, 4 GiB
gdtr:   dw 23
        dd gdt
        times 412 - ($ - $$) db 0
dap:    db 16, 0                ; disk address packet: a piece to 0000:8000, from the
        dw CHUNK                ; sector the image begins at on
        dw LOAD, 0
        dq 0                    ; What tools/mkdisk.py fills in: that sector,
dest:   dd 0                    ; where the image goes (its header's load address),
entry:  dd 0                    ; where it is entered, and its length in sectors;
left:   dd 0
        times 6 db 0
        times 64 db 0           ; and the partition table: one partition, the rest of the disk
        dw 0xAA55
