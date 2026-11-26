; dhcp.asm: the DHCP client, in an image that has no address of its own. A part of os.asm,
; which includes it.
%ifndef OURIP
; ----------------------------------------------------------------------------
; Our address, where the image has none of its own: a DHCP server's to give (RFC 2131). We
; ask everybody for one (DISCOVER); a server offers one (OFFER); we ask that server for it
; (REQUEST); it says yes (ACK), and for how long. Half that time later we ask to keep it
; (REQUEST again, with the address as ours), and so on for as long as we are up. That is
; all of it: who our neighbours are and where the world is we need not be told, since
; every frame of ours answers one, and goes to where that one came from.
; All of this is the first processor's: it asks when it is time (DHT), and what may be an
; answer is given to it and no other (`drain`), so what is known of the asking (DHT, DHB,
; DHX, DHA: from rbp on, here) has one reader and one writer. What the others read is the
; outcome, MYIP.
; If no answer comes we ask again, after 2 s, 4 s, 8 s, ... and then every 128 s, for ever.
; An address that we could not get renewed is used on: a server that gives up its address
; is no server.
;
; dhask (every turn of the first processor's polling loop): if it is time, ask. With no
; address, for one; with one, to keep it, as a client asks that has heard nothing from
; its own server: everybody. Every question has a number of its own (DHX, from `rand`):
; an answer has to carry it, so whoever has seen a question's number, or means to guess
; one, has until the next question. (Clobbers everything. By the clock as it was last
; read: a frame or an idle turn ago.)
dhnot:  ret                     ; (not yet)
dhask:  mov ebp, MYIP
        mov eax, [TNOW]
        sub eax, [rbp+DHT-MYIP] ; (how late it is)
        js dhnot
        mov cl, [rbp+DHB-MYIP]  ; (the how manieth time, up to 7: so long until the next,
        cmp cl, 7               ; from now)
        adc cl, 0
        mov [rbp+DHB-MYIP], cl
        mov edx, 2048
        shl edx, cl
        add eax, edx
        add [rbp+DHT-MYIP], eax
        lea edi, [rbp+DHX-MYIP]
        push 1
        pop rcx
        call rand
        count 10
        mov eax, [rbp]          ; What is asked for: our address, to keep it; or any (an
        mov [rbp+DHA-MYIP], eax ; offer will say which)
        push 1                  ; DISCOVER,
        pop rdx
        test eax, eax
        jz dhsend
        mov dl, 3               ; or REQUEST (which names no address but as the sender's)
        xor eax, eax
; dhsend: a DHCP message of type dl, to everybody: 1, DISCOVER; or 3, REQUEST, which asks
; to keep the address we have (eax = 0), or for the address eax that a server has offered
; (whose name for itself is the upper half of rdx). 342 bytes: the least such a message
; may have (300, behind the headers), nearly all of them zero. (rbp = MYIP. Clobbers
; everything.)
dhsend: push rdx
        push rax
        call txbuf
        mov edi, ebx
        xor eax, eax
        mov ecx, 342
        rep stosb
        mov edi, ebx
        dec eax
        stosd
        stosw                   ; To everybody,
        mov esi, MAC
        movsd
        movsw                   ; from us:
        mov esi, DHHDR          ; IPv4, UDP from port 68 to port 67, a request
        mov cl, DHHLEN
        rep movsb
        mov eax, [rbp+DHX-MYIP]
        stosd                   ; with the question's number,
        mov cl, [rbp+DHB-MYIP]  ; asked for about so many seconds now (1, 2, 4, ...: a
        mov al, 1               ; server may be told to leave a client to others until it
        shl al, cl              ; has asked for a while),
        mov [rbx+51], al
        mov eax, [rbp]
        mov [rbx+26], eax       ; from our address, if we have one,
        scasd
        stosd                   ; which is then also what we say is ours (ciaddr),
        add edi, 12
        lea esi, [rbx+6]
        movsd
        movsw                   ; by the owner of our card's address (chaddr).
        lea edi, [rbx+278]
        mov eax, 0x63538263     ; Then the options: the four bytes that say there are any,
        stosd
        mov eax, 0xFF000135     ; which message this is (53), and that this was all (255)
        stosd
        pop rax
        pop rdx
        mov [rdi-2], dl
        test eax, eax
        jz .sum
        mov word [rdi-1], 0x0432 ; or, before that: which address we ask for (50), and
        inc edi                 ; whose offer it was (54)
        stosd
        mov ax, 0x0436
        stosw
        shr rdx, 32
        xchg eax, edx
        stosd
        dec byte [rdi]
.sum:   lea esi, [rbx+14]       ; (the IP header's checksum. UDP's is left out, as it may be)
        push 20
        pop rcx
        call csum
        mov [rbx+24], ax
        mov ecx, 342
        jmp txgo

; dhcp: what may be a DHCP server's message: the frame in FR, which is UDP and whole
; (`tcp`: ecx = its length behind the IP header, ax = its checksum, 0 if right; ebx = 0).
; It counts if that is right or left out (0 in its place), if it is from port 67 to port
; 68, has the number of the question we are asking, and we are asking (so nobody can
; tell us our address at a time of their choosing). Behind 240 bytes of fixed fields come
; the options: which, how long, value, as far as the message goes (the lengths are the
; sender's: an option counts if all of it lies inside the message; one too short to have
; any has none, and says nothing). Three matter, and the first four bytes of each are
; kept: for how long the address is ours (51: seconds; if not said, for ever), which
; message this is (53), and what the server calls itself (54).
;   An offer (2), while we have no address and have asked for none (DHA): we ask that
;     server for the address it offers. Others' offers for the same question get nothing:
;     a request that names another server would tell the first that we take its offer
;     back.
;   Yes (5, ACK) to the address we asked for (the one offered, or ours): it is ours. Half
;     its time from now, but after 2^19 s (six days) at the latest, we ask to keep it.
;   No (6, NAK): we have no address, and ask anew a second from now.
; (Clobbers everything.)
dhnone: ret                     ; (not an answer to us: the near `ret` for where `dhcp` begins)
dhcp:   test ax, ax
        jz .sum
        cmp [rbx+40], bx
        jne dhnone
.sum:   cmp dword [rbx+34], 0x44004300
        jne dhnone
        mov ebp, MYIP
        mov eax, [rbp+DHX-MYIP]
        cmp [rbx+46], eax
        jne dhnone
        cmp [rbp+DHB-MYIP], bl
        je dhnone
        lea edi, [rbx+rcx+34]   ; Where the message ends (and four zero bytes behind it:
        mov [rdi], ebx          ; what is read of a value is the message's, or that).
        push rbx                ; What the options say, by number, from 51 on: four bytes
        push -1                 ; each (none yet: for ever, no message, nobody's)
        mov esi, 282            ; (FR + 282: the first option)
.opt:   lea eax, [rsi+2]
        cmp eax, edi
        ja .seen
        lodsw                   ; which, and how long
        test al, al
        jnz .o
        dec esi                 ; (padding is a byte)
        jmp .opt
.o:     cmp al, 255             ; (the end)
        je .seen
        movzx edx, ah
        add edx, esi            ; where this one ends
        cmp edx, edi
        ja .seen
        sub al, 51
        cmp al, 3
        ja .nx
        movzx eax, al
        mov ecx, [rsi]
        mov [rsp+rax*4], ecx
.nx:    mov esi, edx
        jmp .opt
.seen:  pop rcx                 ; for how long (as it was sent),
        pop rdx                 ; which message, and (the upper half) whose
        xor eax, eax
        cmp dl, 6
        je .no
        or eax, [rbx+58]        ; the address it is about (one that names none says
        jz .ret                 ; nothing)
        cmp dl, 5
        je .yes
        cmp dl, 2
        jne .ret
        cmp [rbp], ebx
        jne .ret
        cmp [rbp+DHA-MYIP], ebx
        jne .ret
        mov [rbp+DHA-MYIP], eax
        inc dl                  ; (a REQUEST)
        jmp dhsend
.yes:   cmp eax, [rbp+DHA-MYIP]
        jne .ret
        count 11
        jmp short .set
.no:    xor ecx, ecx            ; (no address, eax = 0; and anew in a second)
.set:   mov [rbp], eax
        bswap ecx               ; (seconds: 1,024 ticks are half of one)
        mov eax, DHMAX
        cmp ecx, eax
        cmova ecx, eax
        shl ecx, 10
        call clock
        lea eax, [rax+rcx+2048]
        mov [rbp+DHT-MYIP], eax
        mov [rbp+DHB-MYIP], bl
.ret:   ret
%endif
