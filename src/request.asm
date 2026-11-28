; request.asm: a client's TLS record, and the response its request picks. A part of os.asm, which includes it.
; record: one record from the client of connection rbp, at rsi (edx bytes with its header).
; If it is not what the client's next record would be under its key, it is nothing to us:
; the client's Finished (which has other keys), anything forged, anything a second time.
; If it is, it counts. And if it is a request, the response it asks for becomes the one in
; hand (see `tcp.tx`): for GET and HEAD the one the site has for the path, or the one
; that says there is none (or, without a Host line, the one that says no and closes the
; connection); for what else begins like a request, the one that says no and
; closes the connection. CF: that can't be yet, because the client has not acknowledged
; all of the response before: the record is then to be taken as not arrived. Keeps all
; registers.
record: pushad
        cmp byte [rsi], 23      ; application data: what everything encrypted says it is
        jne .no
        lea ecx, [rdx-21]       ; what it holds, between its header and its tag
        test ecx, ecx
        jle .no
        add esi, 5
        lea rbx, [rbp+C_KIV+44] ; the client's key,
        mov edx, [rbp+C_ST]
        dec edx                 ; and the number this record must have
        mov edi, VB
        stc
        call seal               ; VB = what it says, and behind that the tag it should have:
        movdqu xmm0, [rdi-16]   ; all 16 bytes are looked at, whatever they are
        movdqu xmm1, [rsi+rcx]
        pxor xmm0, xmm1
        ptest xmm0, xmm0
        jne .no
        mov esi, VB             ; It is the client's. Behind what it says comes the byte that
.pad:   dec ecx                 ; says what that is, and after it there may be zeros
        js .last                ; (zeros and no such byte: nobody's record. RFC 8446, 5.4)
        cmp byte [rsi+rcx], 0
        je .pad
        cmp byte [rsi+rcx], 23
        jne .count              ; (an alert: the client is leaving)
        xor ebx, ebx
        cmp ecx, 4               ; Do not classify a short plaintext from stale VB bytes
        jb .other
        cmp dword [rsi], "GET "
        je .get
        cmp dword [rsi], "HEAD"
        jne .other
        cmp ecx, 5               ; HEAD needs its following space within this plaintext
        jb .other
        cmp byte [rsi+4], ' '
        jne .other
        mov bh, 0x80            ; (only the head)
        inc esi
        dec ecx
.get:   push rsi                ; A request needs a Host line, and one without is told so
        push rcx                ; and closed (RFC 9112, 3.2)
        push rbx
        mov edi, H_HOST
        push 6
        pop rdx
        mov bh, 0
        call seek
        pop rbx
        pop rcx
        pop rsi
        mov eax, A_400
        jc .have
        add esi, 4
        sub ecx, 4
        mov edi, 0x811C9DC5     ; The path, up to a space, a question mark or the end, and
        xor edx, edx            ; its hash (FNV-1a)
.pc:    cmp edx, ecx
        jae .pe
        movzx eax, byte [rsi+rdx]
        cmp al, ' '
        jbe .pe
        cmp al, '?'
        je .pe
        xor edi, eax
        imul edi, edi, 0x01000193
        inc edx
        jmp .pc
.pe:    mov r9d, ecx            ; (what is left of the request, the path included)
        mov eax, edi            ; The site's table of paths (tools/pack.py): from the place
.pr:    and eax, PT_MASK        ; the hash names on, until one is empty
        mov ecx, [SITE+rax*8+4]
        jrcxz .nf
        cmp [SITE+rax*8], edi
        jne .nx
        cmp [SITE+rcx+2], dx
        jne .nx
        pushad
        lea edi, [SITE+rcx+4]
        mov ecx, edx
        repe cmpsb
        popad
        je .hit
.nx:    inc eax
        jmp .pr
.hit:   movzx eax, word [SITE+rcx] ; The response for that path. Of its forms, the one for
        add esi, edx            ; this client: the header lines behind the path say which
        mov ecx, r9d
        sub ecx, edx
        call pick
        jmp .have
.other: xor edx, edx            ; Not a request we answer. One that begins like a request
.word:  cmp edx, ecx            ; (a method, which is any word, and a space: RFC 9110, 9.1)
        jae .said               ; Never scan beyond the authenticated plaintext
        mov al, [rsi+rdx]       ; is told so. A header's line is none: its word ends with
        inc edx                 ; A header's line is none: its word ends with
        cmp al, ':'             ; a colon. (What the record says ends before a byte 23,
        je .count               ; so this ends there at the latest.)
        cmp al, ' '
        ja .word
        jb .count
.said:  dec edx
        jz .count
        mov eax, A_405
        jmp .have
.nf:    mov eax, A_404
.have:  or eax, ebx
        call geom               ; Has the client all of the response before?
        mov ecx, [TXEND]
        cmp ecx, [rbp+C_ACK]
        jne .wait
        mov ecx, [TXN]
        add [rbp+C_SR], ecx     ; The new one's records are numbered on from its,
        mov [rbp+C_AS], ax
        mov ecx, [rbp+C_SND]
        mov [rbp+C_RS], ecx     ; and it begins where we are
        and byte [rbp+C_FLG], ~F_DUP3
        cmp byte [rbp+C_CW], WIN ; (and it starts with no fewer segments on their way
        jae .win                ; than any connection may start with,
        mov byte [rbp+C_CW], WIN
.win:   cmp byte [rbp+C_CW], 44 ; and no more than 64 KB of them, whatever the one before
        jbe .w44                ; got to: all at once, they would be lost in heaps)
        mov byte [rbp+C_CW], 44
.w44:   and eax, 0x7FFF
        shl eax, 4
        test byte [SITE+AT_OFF+rax+12], 1
        jnz .last               ; One after which we close. And so we do when our key has
        cmp dword [rbp+C_SR], 1 << KEYLIFE ; sealed 2^24 records: it should not seal more
        jae .last               ; than 2^24.5 (RFC 8446, 5.5; the response in hand may
.count:                         ; take 2^22.4), and we have no way to change it
%ifdef STLIFE
        cmp dword [rbp+C_ST], 1 << STLIFE ; (make STLIFE=n, for tests)
%else
        cmp dword [rbp+C_ST], -2 ; (nor may the client's counter wrap to "no ClientHello")
%endif
        jb .st
.last:  or byte [rbp+C_FLG], F_CLOSED
.st:    inc dword [rbp+C_ST]
        mov eax, [rbp+C_ACK]
        mov [rbp+C_SACK], eax
        or byte [rbp+C_FL2], F_SACK
.no:    clc
        popad
        ret
.wait:  stc
        popad
        ret

; pick: the form of response eax that the client who asks for it is to get. A file can be
; in the site several times (tools/pack.py; its flags say how): as it is, and compressed,
; for a client whose Accept-Encoding names the way (brotli before gzip); and behind each
; of these, the answer for a client that has it already: one whose If-None-Match names
; its ETag, which that answer has at a known place. The request's header lines are the ecx
; bytes at rsi. Returns eax. (Header names are looked for at the start of a line, their
; letters small or capital; what a name's line holds is looked through as far as it goes.)
pick:   pushad
        mov ebp, eax
        shl eax, 4
        mov bl, [SITE+AT_OFF+rax+12]
        mov r10d, esi
        mov r11d, ecx
        test bl, 6
        jz .inm
        mov edi, H_AE
        push H_INM - H_AE
        pop rdx
        call .line
        jc .inm
        test bl, 4
        jz .gz
        mov edi, T_BR
        mov dl, 2
        call .tok
        jc .gz
        add ebp, 4
        jmp .inm
.gz:    mov edi, T_GZ
        mov dl, 4
        call .tok
        jc .inm
        inc ebp
        inc ebp
.inm:   test bl, 8
        jz .done
        mov edi, H_INM
        push T_BR - H_INM
        pop rdx
        call .line
        jc .done
        lea eax, [rbp+1]        ; (the "not modified" of the form picked: the ETag in it)
        shl eax, 4
        mov edi, [SITE+AT_OFF+rax]
        add edi, SITE + ETAG_AT
        mov dl, ETAG_LEN
        mov bh, 10
        call seek
        jc .done
        inc ebp
.done:  mov [rsp+48], ebp
        popad
        ret
.line:  mov esi, r10d           ; (rsi, ecx = what follows the header name at rdi, if the
        mov ecx, r11d           ; request has a line that begins with it; else CF)
        mov bh, 0
        jmp seek
.tok:   push rsi                ; (CF unless the line at rsi names the way of compressing
        push rcx                ; at rdi, and not as one it does not want: "q=0")
        mov bh, 10
        call seek
        jc .t
        cmp dword [rsi], ";q=0"
        clc
        jne .t
        stc
.t:     pop rcx
        pop rsi
        ret

; seek: CF unless the edx bytes at rdi are among the ecx bytes at rsi, before a byte bh (a
; line's end; 0: none). The bytes at rsi count with their bit 5 set, so that a letter is
; found small or capital (and a line end as the "*" the header names begin with). If
; found: rsi = behind them, ecx = how many bytes follow. (Clobbers al, r8.)
seek:   cmp ecx, edx
        jb .ret
        xor r8d, r8d
.c:     mov al, [rsi+r8]
        or al, 0x20
        cmp al, [rdi+r8]
        jne .nx
        inc r8d
        cmp r8d, edx
        jb .c
        add esi, edx
        sub ecx, edx
.ret:   ret
.nx:    cmp [rsi], bh
        stc
        je .ret
        inc esi
        dec ecx
        jmp seek
