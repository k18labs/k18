; tls.asm: the TLS 1.3 handshake. A part of os.asm, which includes it.
; ----------------------------------------------------------------------------
; handshake: ClientHello message at rsi (ecx bytes), connection at rbp.
; Writes our flight to OB (the ServerHello, a ChangeCipherSpec, and the rest in one sealed
; record), returns edi = end. Clobbers all but rbp.
handshake:
        push rbp
        push rcx                ; (the ClientHello's length)
        movzx edx, byte [rsi+38] ; session id length
        lea eax, [rsi+rdx+41]   ; behind it the cipher suites (two bytes each), after their
        lea r8d, [rsi+rcx]      ; length, which counts as far as the ClientHello goes
        movzx ecx, word [rax-2]
        xchg cl, ch
        or edi, -1              ; Ours, 13 01 (AES-128-GCM), among the client's: SUITE is
        sub r8d, eax            ; 0 if it names it, -1 if not
        jbe .cse
        cmp ecx, r8d
        jbe .csn
        mov ecx, r8d
.csn:   shr ecx, 1
        jz .cse
.cs:    cmp word [rax], 0x0113
        je .cs1
        inc eax
        inc eax
        loop .cs
        jmp .cse
.cs1:   inc edi
.cse:   mov [SUITE], edi
        pop rcx
        mov edi, TR             ; The transcript. If this is the ClientHello we asked for
        test byte [rbp+C_FL2], F_HRR ; (below), it begins with what stands for the first
        jz .ch                  ; one, its hash, and with our request, which is made again
        mov eax, 0x200000FE     ; from this one (the two have the same session id and suites)
        stosd
        push rsi
        push rcx
        lea rsi, [rbp+C_KIV]
        push 4
        pop rcx
        rep movsq
        mov rsi, [rsp+8]
        call hrrmsg
        pop rcx
        pop rsi
.ch:    mov r10d, edi           ; the ClientHello
        push rsi
        rep movsb
        pop rsi
        mov ebx, edi            ; the ServerHello goes here
        ; What the client offers. Behind the session id, the cipher suites and the
        ; compression methods come the extensions: type, length, data (two bytes each for
        ; the first two). Three matter: the versions (43: TLS 1.3 must be among them), the
        ; groups (10: is x25519 among them?) and the key shares (51: group, length, key;
        ; ours is group 29 with 32 bytes). Every length is the client's: an extension
        ; counts if all of it lies inside the ClientHello, and what is looked at inside
        ; one lies inside that extension. (The x25519 share is found by walking the key
        ; shares, not by searching for its four bytes 00 1d 00 20: a client's other key
        ; shares are a kilobyte of random-looking bytes, which can hold those four.)
        push rsi
        xor edx, edx            ; dl, bit 0: TLS 1.3 is offered, bit 1: x25519 is
        xor r11d, r11d          ; where the x25519 key share is (0: nowhere)
        lea edi, [r10+38]
        movzx ecx, byte [rdi]   ; session id (these two lengths are within reach in any case:
        lea edi, [rdi+rcx+1]    ; the transcript has room for a ClientHello of any size)
        movzx ecx, word [rdi]
        xchg cl, ch             ; cipher suites
        lea edi, [rdi+rcx+2]
        cmp edi, ebx
        jae .seen
        mov r9d, edi            ; (the compression methods: see `.seen`)
        movzx ecx, byte [rdi]   ; compression methods, and the extensions' length
        lea edi, [rdi+rcx+3]
.ext:   lea esi, [rdi+4]
        cmp esi, ebx
        ja .seen
        movzx eax, word [rdi+2]
        xchg al, ah
        add esi, eax            ; where this extension ends
        cmp esi, ebx
        ja .seen
        movzx ecx, word [rdi]   ; which it is
        add edi, 5              ; The versions (after a length of one byte): is TLS 1.3
        mov ax, 0x0403          ; among them?
        mov dh, 1
        cmp cx, 0x2b00
        je .list
        inc edi                 ; The groups (after a length of two bytes): is x25519?
        mov ax, 0x1d00
        mov dh, 2
        cmp cx, 0x0a00
        je .list
        cmp cx, 0x3300
        jne .nxt
.ks:    lea eax, [rdi+36]       ; The key shares: group, length, key
        cmp eax, esi
        ja .nxt
        cmp dword [rdi], 0x20001d00 ; (x25519, 32 bytes)
        jne .nks
        mov r11d, edi
.nks:   movzx eax, word [rdi+2]
        xchg al, ah
        lea edi, [rdi+rax+4]
        jmp .ks
.list:  lea ecx, [rdi+2]        ; (is the word ax among the words up to the extension's end?)
        cmp ecx, esi
        ja .nxt
        cmp [rdi], ax
        mov edi, ecx
        jne .list
        or dl, dh
.nxt:   mov edi, esi
        jmp .ext
        ; A client we can't serve is told so, and that is the connection: one that has no
        ; TLS 1.3 (an alert "protocol version"), one that does not name our cipher suite,
        ; one that has no x25519, or sent no share for it after being asked ("handshake
        ; failure"), or one whose share makes the shared secret all zeros ("illegal
        ; parameter", RFC 8446, 7.4.2). It gets nothing that only looks like an answer.
.seen:  pop rsi
        mov al, 10              ; ("unexpected message": the first is a ClientHello, type 1,
        cmp byte [rsi], 1       ; RFC 8446, 4)
        jne .alert
        mov al, 70
        test dl, 1
        jz .alert
        mov al, 50              ; ("decode error": a session id is 32 bytes at most, RFC 8446,
        cmp byte [rsi+38], 32   ; 4.1.2. Our ServerHello has the client's, and with a longer
        ja .alert               ; one its lengths would not fit their one byte;
        mov edi, [rsi]          ; and the message is as long as it says, which is what the
        bswap edi               ; record holds: 01, and in three bytes its length without
        lea ecx, [rbx+0x00FFFFFC] ; these four)
        sub ecx, r10d
        cmp ecx, edi
        jne .alert
        mov al, 47              ; ("illegal parameter": of compression methods there is one,
        cmp word [r9], 1        ; none: 01 00, RFC 8446, 4.1.2. TLS 1.3 is among the client's
        jne .alert              ; versions, so it has extensions, and r9 is where these are)
        mov al, 40
        cmp dword [SUITE], 0
        jl .alert
        test r11d, r11d
        jnz .has
        test byte [rbp+C_FL2], F_HRR
        jnz .alert
        test dl, 2
        jz .alert
        ; No share for x25519, but the client has it: it is asked for a ClientHello with
        ; one (a HelloRetryRequest, which is all of our flight this time). The connection
        ; goes on waiting for a ClientHello, and keeps, where its keys will be, the hash of
        ; this one: the transcript has that in its place.
        or byte [rbp+C_FL2], F_HRR
        push rsi
        mov esi, r10d
        mov ecx, ebx
        sub ecx, esi
        lea rdi, [rbp+C_KIV]
        call sha256
        pop rsi
        mov edi, OB
        mov dword [rdi], 0x00030316
        add edi, 5
        call hrrmsg
        mov eax, edi
        sub eax, OB + 5
        xchg al, ah
        mov [OB+3], ax
        pop rbp
        ret
.alert: mov edi, OB
        mov dword [rdi], 0x00030315 ; an alert record of two bytes:
        mov word [rdi+4], 0x0202 ;  fatal,
        mov [rdi+6], al         ;   and why
        add edi, 7
        or byte [rbp+C_FLG], F_CLOSED ; (our FIN goes with it: `tcp.fin`)
        pop rbp
        ret
.has:   mov eax, r11d
        push rax                ; (the key is 4 bytes on from there)
        push rsi
        mov esi, HT             ; the transcript's hash starts over
        mov edi, TSH
        push 8
        pop rcx
        rep movsd
        mov dword [TPOS], TR
        pop rsi
        mov edi, E              ; a fresh secret: our X25519 scalar
        mov cl, 4
        call rand
        movzx edx, byte [rsi+38] ; session id length
        mov edi, ebx
        lea ecx, [rdx+39]
        rep movsb               ; ServerHello: as the ClientHello up to its session id,
        mov word [rbx+4], 0x0303 ; but with the version a ServerHello has (RFC 8446, 4.1.3),
        lea edi, [rbx+6]
        mov cl, 4
        call rand               ; but with a random of our own, ...
        lea edi, [rbx+rdx+39]
        mov esi, SHTAIL
        mov cl, 19
        rep movsb               ; ... + suite, extensions, key share header ...
        pop rsi
        lodsd
        call xdh                ; ... + our key share; R_X = the shared secret
        mov rax, [R_X]
        or rax, [R_X+8]
        or rax, [R_X+16]
        or rax, [R_X+24]
        mov al, 47
        jz .alert
        lea eax, [rdx+86]
        shl eax, 24
        mov al, 2
        mov [rbx], eax          ; type 2, length

        mov ebp, SLOTS + 128    ; key schedule: what comes before the shared secret is the
        push rbx                ; same every time (boot made it)
        lea ebx, [rbp+S_D1]
        mov esi, R_X
        mov cl, 32
        mov edi, ebp
        call hmac               ; handshake secret
        pop rbx
        lea eax, [rbx+rdx+90]   ; P1 = end of ServerHello
        call thash
        push rbx
        push rdx
        mov ebx, ebp
        mov esi, L_SHTS
        lea edx, [rbp+S_TH]
        lea edi, [rbp+S_TS]
        call expand             ; server handshake traffic secret
        pop rdx
        pop rbx
        xchg eax, edi           ; EncryptedExtensions + Certificate
        mov esi, EECERT
        mov ecx, EECERT_LEN
        rep movsb
        xchg eax, edi           ; eax = P2
        call thash
        push rax
        mov edi, CVB            ; CertificateVerify content: 64 spaces | context | hash
        mov al, 0x20
        mov cl, 64
        rep stosb
        mov esi, CVCTX
        mov cl, 34
        rep movsb
        lea esi, [rbp+S_TH]
        mov cl, 32
        rep movsb
        mov esi, CVB
        mov cl, 130
        call sha256             ; the hash to sign (behind the content)
        mov esi, edi
        call sign               ; r and s
        pop rsi                 ; P2. The CertificateVerify message: 0f 00 00 n+6 | 04 03 |
        lea edi, [rsi+10]       ; 00 n+2 | 30 n | r | s, the two as DER INTEGERs (n bytes)
        push rsi
        mov esi, R_X
        call derint
        add esi, 32
        call derint
        pop rsi
        mov eax, edi
        sub eax, esi
        sub eax, 10
        mov dword [rsi], 0x0F
        mov dword [rsi+4], 0x0304
        mov byte [rsi+8], 0x30
        mov [rsi+9], al
        add al, 2
        mov [rsi+7], al
        add al, 4
        mov [rsi+3], al
        xchg eax, edi           ; eax = P3 = end of CertificateVerify

        mov edi, OB             ; ServerHello record
        mov dword [rdi], 0x00030316
        lea ecx, [rdx+90]
        mov [rdi+4], cl
        add edi, 5
        mov esi, ebx
        rep movsb
        push rsi                ; P1 = end of ServerHello = start of the encrypted part
        push rdi                ; output position
        lea ebx, [rbp+S_TS]
        mov edi, KH
        call keys               ; handshake key and iv

        mov esi, L_FIN
        xor edx, edx
        lea edi, [rbp+S_D]
        call expand
        mov ebx, edi            ; finished key
        call thash
        xchg eax, edi
        mov eax, 0x20000014
        stosd
        lea esi, [rbp+S_TH]
        mov cl, 32              ; (ecx = 0 after the copy above)
        call hmac
        add edi, ecx
        xchg eax, edi           ; eax = the end of the transcript so far

        pop rdi                 ; output position
        pop rsi                 ; P1
        mov ecx, eax
        sub ecx, esi
        mov ebx, KH
        push rax
        mov eax, 0x00030314     ; Behind the ServerHello's record a ChangeCipherSpec, 14 03 03
        stosd                   ; 00 01 01, whatever the client is: it is to pass over one
        mov al, 1               ; at any time before our Finished (RFC 8446, 5), and to
        stosb                   ; what stands in between and takes this for TLS 1.2, what
        stosb                   ; follows is then that connection's encrypted rest (D.4)
        mov al, 0x16            ; what the record holds: handshake messages
        xor edx, edx            ; (its number; and CF = 0: encrypt)
        call seal               ; edi = end of output
        pop rax

        call thash              ; application traffic secret
        push rdi
        mov ebx, ebp
        mov esi, L_DER
        lea edx, [rbp+S_EH]
        lea edi, [rbp+S_D]
        call expand
        mov ebx, edi
        lea esi, [rbp+S_Z]
        push 32
        pop rcx
        lea edi, [rbp+S_ES]
        call hmac               ; master secret
        mov ebx, edi
        mov esi, L_CATS
        lea edx, [rbp+S_TH]
        lea edi, [rbp+S_D]
        call expand             ; client application traffic secret
        mov ecx, edi
        mov esi, L_SATS
        lea edi, [rbp+S_TS]
        call expand             ; server application traffic secret
        mov ebx, edi
        pop rax                 ; end of output
        pop rbp
        mov edi, KA
        call keys
        mov ebx, ecx
        add edi, 44
        call keys
        mov esi, KA             ; (`keys` writes 20 bytes too many: not into the connection)
        lea rdi, [rbp+C_KIV]
        push 22
        pop rcx
        rep movsd
        and byte [rbp+C_FL2], 0xF0 ; (the window's shift stays)
        inc dword [rbp+C_ST]
        xchg eax, edi
        ret

; hrrmsg: a HelloRetryRequest for the ClientHello at rsi, to rdi (which moves on): a
; ServerHello as we make them, as that ClientHello up to its session id, but with the
; random that says what it is, SHA-256("HelloRetryRequest"), and after our cipher suite, of
; the key share only the group we want one for. (Clobbers eax, ecx, edx.)
hrrmsg: push rsi
        movzx edx, byte [rsi+38]
        lea ecx, [rdx+39]
        mov eax, edi
        rep movsb
        add edx, 52
        shl edx, 24
        mov dl, 2
        mov [rax], edx          ; type 2, length
        mov word [rax+4], 0x0303 ; (its version: not the client's)
        push rdi
        lea edi, [rax+6]
        mov esi, L_HRR
        push 17
        pop rcx
        call sha256
        pop rdi
        mov esi, SHTAIL
        rep movsb               ; (17 of its 19 bytes: no key follows)
        mov byte [rdi-13], 12   ; twelve bytes of extensions,
        mov byte [rdi-3], 2     ; two of key share
        pop rsi
        ret

; derint: the 32-byte number at rsi (little-endian) as a DER INTEGER to rdi, which moves on:
; no more bytes than it takes, and a zero byte in front if the first has its top bit set
; (clobbers eax, ecx)
derint: push 32
        pop rcx
.z:     cmp byte [rsi+rcx-1], 0
        jne .nz
        loop .z
        inc ecx
.nz:    mov al, 2
        stosb
        mov al, cl
        test byte [rsi+rcx-1], 0x80
        jz .len
        inc eax
        stosb
        mov al, 0
.len:   stosb
.b:     mov al, [rsi+rcx-1]
        stosb
        loop .b
        ret

; thash: TH slot = SHA256(transcript up to eax). The transcript is hashed as it grows:
; TSH is its state after the whole blocks before TPOS, and each call takes in the whole
; blocks that have come since, then finishes a copy of that state.
thash:
        pushad
        mov edx, eax
        sub edx, TR             ; the transcript's length
        mov esi, [TPOS]
        mov ecx, eax
        sub ecx, esi
        push rcx
        push rdx
        shr ecx, 6
        mov edi, TSH
        call shablk
        mov [TPOS], esi
        push rsi
        mov esi, edi
        mov edi, SH
        push 8
        pop rcx
        rep movsd
        pop rsi
        pop rdx
        pop rcx
        and ecx, 63
        call shaend
        mov rbp, [rsp+16]
        lea edi, [rbp+S_TH]
        call shaout
        popad
        ret
