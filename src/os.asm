; os.asm - bare-metal HTTPS server, flat image loaded at 1 MiB and a few bytes (DELTA,
;       below: so many that its code ends where a page does; nasm -f bin)
;
; Boot: by src/boot.asm from a disk, or as a multiboot v1 "a.out kludge" kernel (GRUB,
;       `qemu -kernel`). Sets up long mode, its own segments, stack and zeroed memory, and
;       starts the other processors if there are any (up to MAXCPU in all).
; CPU:  64-bit, with rdrand (secrets), AES and PCLMULQDQ (the hash that places connections;
;       AES-GCM), SSE4.1, and BMI2 and ADX (mulx, adcx, adox: the curves).
; NIC:  virtio-net (modern PCI interface), polled. Our address is what a DHCP server gives
;       us (`dhcp`), or the one the image is built with (make IP=a.b.c.d: OURIP). And, if
;       the image is built with one, an IPv6 address beside it (make IP6=...: `tcp6`).
; TCP:  ports 443 (TLS) and 80 (one response for everybody: the page, or where to go); see `tcp`.
; TLS:  1.3, TLS_AES_128_GCM_SHA256, X25519 (asked for
;       with a HelloRetryRequest if need be), ecdsa_secp256r1_sha256.
; HTTP: GET and HEAD for the files of the site the image ends with (tools/pack.py); see `record`.
; It is meant to be secure: a fresh X25519 key and a fresh ECDSA nonce per
; handshake (rdrand), a real certificate chain, client records are authenticated before
; they are read, and no memory is both written and executed. See docs/internals.md for the
; shortcuts that remain.
;
; Convention: a routine keeps the eight registers of old (pushad/popad: macros here) unless
; it says otherwise; r8-r15 and the SSE registers are scratch, the crypto's to use. All
; buffers live at fixed addresses in zeroed RAM at 2 MiB: one set for each processor (see
; MAXCPU below).
;
; Memory, as the page tables built at boot show it (2 MiB pages): the first 16 MiB as they
; are, and behind them, in one piece, all the other RAM the loader's memory map names,
; wherever it is (also above 4 GiB): the "table space", which the handshake buffers and
; the two connection tables fill. So a slot's address takes 64 bits; everything else is
; below 4 GiB, and 32-bit registers do for it.
;
; The image ends with the site it serves (tools/pack.py: SITE, at the end of this file), so
; it can be long. Up to 1 MiB of it lies between 1 MiB and 2 MiB, where nothing else is. If it
; is longer, everything that is said to be at "2 MiB" and up here is as much further up as
; it takes (LOW: whole pages of 2 MiB): the buffers, the tables, the table space.

; The files: this one has what all of it shares (where things are, the macros), the few
; pieces between its parts, and what is only read (at its end). The rest is included from
; here, a subsystem a file, in the order it lies in the image: one unit for the assembler.

%use smartalign                 ; (`align` fills with as few instructions as it takes)
%include "conf.inc"             ; CHAIN_LEN

%ifdef HOST
default abs
BSS     equ 0x200000
%else
default rel
; DELTA: the image is loaded so many bytes above 1 MiB, and its header says so to whoever
; loads it. Memory is barred from execution a page (4 KiB) at a time, and the image is
; code, then what is only read (constants, the key, the certificates, the site), with
; nothing in between: so the code has to end where a page ends, and it is the image's
; place in memory that sees to that, not bytes of padding in the image. The build finds
; the number (a multiple of 64, so that what is aligned in here is aligned in memory):
; it assembles once to see where the code ends (SIZING: the last four bytes of that
; output say), and then for good. See `codend`, which refuses any other number.
%ifndef DELTA
%ifndef SIZING
%error "DELTA is not set: the Makefile finds it (or: -DSIZING, to see where the code ends)"
%endif
%define DELTA 0
%endif
%include "site.inc"         ; SITE_LEN, and where things are in the site
%assign LOW ((0x110000 + SITE_LEN + 0x1FFFFF) >> 21 << 21) - 0x200000 ; (the code ends below 1 MiB + 64 KiB)
BSSN    equ 0x200000 + LOW  ; (BSS as a number)
BSS     equ mb - DELTA + 0x100000 + LOW ; 2 MiB (said relative to the image, so that the assembler reaches
%endif                      ; what is there relative to the instruction pointer: a byte less)
FR      equ 0               ; the Ethernet frame being handled. At address 0 (old real-mode
                            ; IVT, unused), so `xor reg, reg` loads it and its fields are a
P_ADV   equ FR + 0          ; byte away: (where our card's address was) how far its ack moved,
P_IP    equ FR + 26         ;   the client's address,
P_PORTS equ FR + 34         ;   its port and ours (as on the wire),
P_SEQ   equ FR + 38         ;   its sequence number (in host order once `tcp` has started)
P_ACK   equ FR + 42         ;   its ack (the same)
P_FL    equ FR + 47         ;   its flags
P_WIN   equ FR + 48         ;   how much it takes beyond its ack (a word, as on the wire)
P_MORE  equ FR + 52         ;   (in place of the urgent pointer) 1: its data is to be
P_EV    equ FR + 53         ;   acknowledged now; and what it means for a response on its
E_ACK   equ 1               ;   way (`tcp.tx`): E_ACK: it wants an ack; E_RTO: something
E_RTO   equ 2               ;   we sent seems lost, E_DUP: or perhaps is, says an ack that
E_DUP   equ 4               ;   repeats; E_SENT: something has gone out that carries our
E_SENT  equ 8               ;   ack; E_NEW: this packet's request has its response
E_NEW   equ 16
E_SACK  equ 32              ;   first retransmit after loss can recover all unsacked ranges
%ifndef HOST
VQ      equ 0x400000 + LOW  ; the two rings, 64 KiB apart (enough for queues of 1024)
PML4    equ VQ + 0x20000    ; page tables (built at boot): the top one,
PDPT0   equ PML4 + 0x1000   ;   the one for the first 512 GiB,
PDDEV   equ PML4 + 0x2000   ;   the page directory for the card's structures,
PT0     equ PML4 + 0x3000   ;   the page table for the first 2 MiB,
PDT     equ VQ + 0x30000    ;   and page directories: 8 bytes for each 2 MiB that is mapped
PDT_END equ VQ + 0xF0000    ;   (room for 192 GiB)
%endif
DEVG    equ 505             ; the card's structures are mapped in this GiB: 4 MiB for each kind
                            ; of structure (1 common, 2 notify, 4 device), at 4 MiB * kind
STACK   equ BSS + 0x200000  ; the stack grows down from 4 MiB
; More processors than one: each of the others has its own page tables, which differ from
; the first one's in two places: the 2 MiB at BSS and the 4 KiB at FR are memory of its own
; (a copy of BSS as the first one had it when it had set everything up). So what is at fixed
; addresses there is per processor, with nothing in the code that says so. What they
; share: the tables and buffers of the table space, the transmit ring (TXLOCK), and what
; is said here.
MAXCPU  equ 4
TRAMP   equ 0x8000          ; where the others start, in real mode (`tramp` is copied there)
TXLOCK  equ 0x9F00          ; held from `txbuf` to `txgo` (not in the page of TRAMP: that one
NCPUM   equ 0x9F04          ; is code); how many processors take frames, less 1 (a power of two, less 1)
TXCNT   equ 0x9F20          ; how many frames have ever been queued for sending (a qword: `txgo`)
MYIP    equ 0x9F0C          ; Where the image has no address of its own: the one a DHCP server
DHT     equ 0x9F10          ;   gave us (0: none yet); and what the first processor, which
DHB     equ 0x9F14          ;   does the asking, knows of that: when to ask next (in ticks
DHX     equ 0x9F18          ;   of 1/2048 s), how often it has asked without an answer (a
DHA     equ 0x9F28          ;   byte; 0: nothing is being asked), the number of the question
                            ;   it is asking (4 of 8 bytes), and the address it is asking
                            ;   for (0: any): see `dhcp`
%ifndef HOST
APMEM   equ 0x900000 + LOW  ; for each other processor 32 KiB: four page tables, its page 0,
APBSS   equ 0xA00000 + LOW  ; and 2 MiB: its BSS
%endif
TR      equ BSS + 0x20000   ; handshake transcript
VB      equ BSS + 0x30000   ; what a client record should look like (for its tag)
SB      equ BSS + 0x40000   ; seal scratch: what the tag is made over
OB      equ BSS + 0x50000   ; our answer to one packet (OBMAX bytes)
HB      equ BSS + 0x0C900   ; HMAC buffer (key pad | message)
INFO    equ HB + 64         ; HKDF info is built right where HMAC wants its message
SH      equ BSS + 0x0CB00   ; SHA-256: the state of the hash being made,
TSH     equ SH + 32         ;   the state of the handshake transcript's hash (see `thash`),
PADB    equ SH + 64         ;   and the end of a message with its padding (two blocks)
KS      equ BSS + 0x0CD80   ; a block of key stream (64-byte aligned)
RK      equ BSS + 0x0CE00   ; AES-128: the eleven round keys of the record at hand,
NB      equ RK + 176        ;   its counter block (nonce | counter),
TAGM    equ NB + 16         ;   what its tag is masked with,
BSWAPM  equ TAGM + 16       ;   how pshufb reverses 16 bytes (made at boot)
HTAB    equ BSWAPM + 16     ; GHASH: H^1 .. H^8 (each times x), then their halves xored
SLOTS   equ BSS + 0x0D500   ; key schedule values, 8 x 32 bytes, addressed from ebp
KH      equ BSS + 0x0D600   ; handshake traffic key | iv
CVB     equ BSS + 0x0D680   ; CertificateVerify content to be signed (+ room for padding)
KT      equ BSS + 0x0D800   ; SHA-256 round constants (computed at boot), 64 dwords; 512-aligned
HT      equ KT + 0x104      ; SHA-256 initial hash (computed at boot), 8 dwords (+ 56 junk)
REGS    equ BSS + 0x0E400   ; the curve machine's 16 registers of four limbs (not in the image's
                            ; page: TCG takes a slow path for every write to a page with code)
E       equ REGS + 0x200    ; our X25519 secret (32 bytes), then
KD      equ E + 64          ; an ECDSA nonce as the table is asked for it (see `stock`),
KOFFV   equ KD + 32         ; and what it has lost on the way there (made at boot)
NPOOL   equ 64              ; ECDSA nonces are made so many at a time (`stock`):
POOLR   equ BSS + 0x10000   ;   r = x(k G) of each,
POOLK   equ POOLR + NPOOL * 32 ; R^2 / k,
POOLZ   equ POOLK + NPOOL * 32 ; and while they are made: Z of k G,
POOLP   equ POOLZ + NPOOL * 32 ; and the partial products of an inversion (`binv`)
XP      equ BSS + 0x12000   ; the curve programs as `vm` runs them (unpacked at boot)
F25519  equ REGS + 0x300    ; the three fields (see `ecinit`): 2^255 - 19,
FP256   equ F25519 + FSIZE  ;   p of P-256
FN256   equ FP256 + FSIZE   ;   and its n. A field is 2^256 - M, then
F_M     equ 32              ;   M,
F_INV   equ 64              ;   -1/M mod 2^64 (0: not a Montgomery field)
F_EXP   equ 72              ;   and the exponent that inverts
FSIZE   equ 104
TABE    equ BSS + 0x100000  ; the multiples of edwards25519's base point that `xdh` adds up,
TABP    equ BSS + 0x120000  ; and those of P-256's that `sign` does (both made at boot)
VST     equ BSS + 0x0F000   ; virtio-net driver state:
MAC     equ VST + 4         ;   our MAC address (6 bytes, from the device)
Q0      equ VST + 16        ;   receive queue: desc, avail, used (addresses), size - 1, used
Q_SEEN  equ 16              ;     entries seen (dwords), and where to notify the device about
Q_NOTE  equ 24              ;     it (a qword)
Q1      equ Q0 + 32         ;   transmit queue, the same
VCAP    equ VST + 88        ;   where the device's structures are, by kind (qwords at 8 * kind)
VMUL    equ VST + 136       ;   (the dword read after each, at 8 * kind: for notify, its offset multiplier)
NV      equ BSS + 0x0F200
RXLEN   equ NV              ; the length of the frame in FR
HSNEXT  equ NV + 4          ; handshake buffers looked at so far (`hsnew`)
NOW     equ NV + 8          ; when the frame came, in units of 64 s (a byte: see C_AGE)
HSMASK  equ NV + 56         ; n - 1 (see TABV)
OOBASE  equ NV + 60         ; where the places for early segments are
TXK     equ NV + 12         ; 1: frames are queued that the device has not been told about
TT      equ NV + 16         ; the table of TLS connections: address (a qword), number of buckets
PT      equ NV + 32         ; the table of connections to port 80: the same
TPOS    equ NV + 48         ; how far the transcript has been hashed (see `thash`)
SUITE   equ NV + 52         ; 0 if the ClientHello names our cipher suite, else -1
POOLN   equ NV + 64         ; how many of the nonces made are left
POOLFILL equ NV + 68        ; how far the next ones are (32 for each k G there is)
CPUN    equ NV + 72         ; which processor this is (0: the one that booted)
CLAIMQ  equ NV + 80         ; the first 8 bytes of the slot `find` chose for a new connection
BORN    equ NV + 88         ; when we booted, in ticks of 1/2048 s (make LIFE=n)
TMMASK  equ NV + 92         ; SYNs that may be answered again (`tnote`): how many places, less 1,
TMF     equ NV + 96         ;   where the SYNs are (128 bytes each: tries left, length, frame),
TMT     equ NV + 100        ;   and where the times they came are (a dword each; 0: none)
THAND   equ NV + 104        ;   how far this processor has got round them (`tidle`),
TNOW    equ NV + 108        ;   the time, in ticks of 1/2048 s (`clock`),
TLAST   equ NV + 112        ;   when a SYN was last answered again,
TTRY    equ NV + 116        ;   and how often the SYN in hand may be yet (0: it is the client's)
RBASE   equ NV + 120        ; the processors' rings of frames (`drain`): where the first one is,
RSTEP   equ NV + 124        ;   how far apart they are,
MYRING  equ NV + 132        ;   and where this processor's is
TXM     equ NV + 136        ; the response in hand (`geom`): the bytes of a segment of it,
TXP     equ NV + 140        ;   how many of them are the response's (the rest is the record's),
TXL     equ NV + 144        ;   the response's length,
TXN     equ NV + 148        ;   in how many records it goes,
TXBLOB  equ NV + 152        ;   where it is,
TXEND   equ NV + 156        ;   the sequence number behind its last byte,
TXLIM   equ NV + 160        ;   and the one up to which the client takes it for now
SEGP    equ NV + 164        ; where the data of the segment in hand began (`tcp.busyc`)
TQB     equ NV + 172        ; this processor's connections that wait for an ack (`tarm`): where
TQH     equ NV + 176        ;   the queue is, how many have been taken out,
TQT     equ NV + 180        ;   how many put in,
TQTRY   equ NV + 184        ;   and (a byte) how often the one in hand has been sent again in vain
TSO     equ NV + 188        ; not 0: the card cuts a frame of ours into segments and sums them
BIGN    equ NV + 192        ; so many such frames this processor has made (`txbig`),
TSCM    equ NV + 200        ; 2^64 / cycles per tick of 1/2048 s (calibrated at boot)
RLAST   equ NV + 208        ; what the processor's random number generator said last (`rand`)
BIGQ    equ BSS + 0x0F100   ;   and for each of its buffers a count of frames queued (TXCNT)
                            ;   that is past the one it last held (qwords)
HKS     equ BSS + 0x0F400   ; the eleven round keys of `prf`, made at boot
HKO     equ HKS + 176       ;   and its output
KA      equ BSS + 0x0F300   ; application keys as `keys` makes them (2 x 44 bytes + 20 of junk)
%ifndef HOST
RXB     equ 0x500000 + LOW  ; receive buffers, 2 KiB each (12-byte virtio header + frame)
TXB     equ 0x700000 + LOW  ; transmit buffers, the same
BIGB    equ 0x1000000 + LOW ; and for each processor BIGS buffers of 64 KiB, for frames that
%endif                      ; the card cuts into segments (`txbig`, `sendrun`)
%ifndef BIGSH
%define BIGSH 3             ; (make BIGSH=n, for tests: 2^n of them)
%endif
BIGS    equ 1 << BIGSH
BIGPAY  equ 0xFF00          ; such a frame holds so many bytes of segments at most
; NOTOURS at, label: to `label` unless the address at `at` is ours: the one the image was
; built with (make IP=a.b.c.d: OURIP, as it is on the wire), or else the one we were given
; (MYIP; while we have none, nothing is for us). (ebx = 0; clobbers eax.)
%macro NOTOURS 2
%ifdef OURIP
        cmp dword [%1], OURIP
%else
        mov eax, [rbx+MYIP]
        test eax, eax
        jz %2
        cmp [%1], eax
%endif
        jne %2
%endmacro
%ifdef IP6A
%define OURIP6              ; (make IP6=...: the image has an IPv6 address, IP6A | IP6B as on the wire)
%endif
%ifdef ISNTOP
%ifndef ISNBITS
%define ISNBITS 12
%endif
ISNLOW  equ (1 << (32 - ISNBITS)) - 1
%endif
%ifndef KEYLIFE
%define KEYLIFE 24          ; (make KEYLIFE=n, for tests: a connection's key seals 2^n records)
%endif
%ifndef WIN
%define WIN 10              ; so many segments of a response may be on their way to begin with (make WIN=n)
%endif
OO_TAG  equ 0               ; A segment that came early (see `oohold`): whose it is: a word of
OO_SEQ  equ 4               ;   the client's hash (0: nobody's), its sequence number,
OO_LEN  equ 8               ;   length
OO_FIN  equ 12              ;   and whether it had a FIN
OO_DATA equ 16
T_TIME  equ 38              ; A connection that waits for an ack (`tarm`) is the first 64 bytes
T_ACK   equ 42              ;   of a frame of its client, and in place of its sequence number,
T_TRY   equ 46              ;   ack and header length: since when, for which ack, the how
T_RTO   equ 0               ;   manieth time; and in place of our card's address's first
                            ;   byte: how long it waits the first time (C_RTO)
%ifndef HOST
TABV    equ (BIGB + (MAXCPU * BIGS << 16) + 0x1FFFFF) & ~0x1FFFFF ; The table space: from 18 MiB up (see the top of this file). Boot
                            ; divides it: n handshake buffers, n places of 2 KiB for early
                            ; segments (n a power of two: about 1/32 and 1/64 of it), 4 n
                            ; SYNs of late (`tnote`), a ring of n frames and a queue of 4 n
                            ; waiting connections for each processor (`drain`, `tarm`), then
                            ; the two connection tables: the one for TLS, the one for port 80.
HSP     equ TABV            ; Handshake buffers (see `hsnew`): each holds
%endif
%assign HS_SHIFT 12
%rep 4
%if CHAIN_LEN + 512 > (1 << HS_SHIFT) - 16
%assign HS_SHIFT HS_SHIFT + 1
%endif
%endrep
%if CHAIN_LEN + 512 > (1 << HS_SHIFT) - 16
%error "the certificate chain is too long for a handshake buffer"
%endif
%if CHAIN_LEN + 5120 > 0x10000  ; (the transcript: the chain, and up to 4,883 bytes of the rest)
%error "the certificate chain is too long for the transcript's 64 KiB"
%endif
HS_OWNER equ 0              ;   the connection it belongs to (its slot: a qword),
HS_FLEN equ 8               ;   the length of our flight (0: not sent yet),
HS_CH   equ 16              ;   and the ClientHello record as far as it has arrived (up to
HS_FL   equ HS_CH           ;   CHMAX), then, in its place, our flight as it was sent
CHMAX   equ (1 << 12) - 16
BUCKET  equ 16              ; slots in a bucket (see `find`)
%ifndef TSHARE
%define TSHARE 3            ; the TLS table gets 1/2^TSHARE of that memory (make TSHARE=n)
%endif
%ifndef IDLE
%define IDLE 64             ; a connection that has been quiet for longer than this (in units of
%endif                      ; 64 s: 68 minutes) may be replaced when a new one finds no room
HINT    equ 0x3FC0          ; see the cookie in `tcp`
OBMAX   equ 0x40000         ; room for one answer at OB

S_Z     equ -128            ; slot offsets from ebp = SLOTS + 128
S_EH    equ -96
S_ES    equ -64
S_D     equ -32
S_HS    equ 0
S_TS    equ 32
S_TH    equ 64
S_D1    equ 96              ; (constant: what the handshake secret is extracted with)

; A connection's slot. One for port 80 is the first PSLOT bytes; one for TLS has it all.
C_IP    equ 0               ; the client's address (0: the slot is free)
C_PORT  equ 4               ; and port (a word)
C_FLG   equ 6               ; a byte: F_CLOSED, F_DEFER, which segment size the client takes
F_CLOSED equ 1              ;   (bits 2-3: MSSTAB), F_SYN; on port 80 whether a line has just
F_DEFER equ 2               ;   ended (bit 7); on 443, in bits 5-6, how many acks in a row have
F_DEFER_BIT equ 1           ;   said the same (F_DUP3: three, and we have sent again what they
F_SYN   equ 16              ;   ask for). F_CLOSED: FINs exchanged, but the client lacks
F_DUP   equ 0x20            ;   something. F_DEFER: its data is not acknowledged before it has
F_DUP3  equ 0x60            ;   our answer. F_SYN: a SYN has come for it since its last ack
                            ;   that fitted
C_AGE   equ 7               ; when its last packet came (NOW; a byte, so after 256 units of
                            ; silence a connection looks young again for a while)
C_NXT   equ 8               ; next sequence number we expect from the client
C_SND   equ 12              ; our next sequence number
C_ACK   equ 16              ; the client's last ack
PSLOT   equ 24
C_ST    equ 20              ; 0 = waiting for the ClientHello, else 1 + the number of the
                            ; client's next record (of those under its application key)
C_SR    equ 24              ; the response in hand (see `tcp.tx`): the number of its first record,
C_RS    equ 28              ;   the sequence number of its first byte (before the first
                            ;   response: of the byte after our flight),
C_AS    equ 32              ;   and which it is (a word: its number in the site; bit 15: only
                            ;   its head)
C_HS    equ 34              ; its handshake buffer + 1 (a word; if that still says so itself)
C_LEN   equ 36              ; a word: so many bytes of a record that came in pieces are in that buffer
C_FL2   equ 38              ; a byte: F_FIN, F_ARMED, and in the top four bits by how many
F_FIN   equ 2               ;   bits the client's window is to be shifted (what its SYN said:
F_ARMED equ 4               ;   window scaling). F_FIN: our FIN has gone out. F_ARMED: it is
                            ;   in the queue of `tarm`.
F_HRR   equ 8               ;   F_HRR (before the handshake): we have asked for a second
F_CA    equ 8               ;   ClientHello; F_CA (after it): something was lost on this
                            ;   connection once.
C_CW    equ 39              ; a byte: so many segments of a response may be on their way (`tcp.tx`)
C_KIV   equ 40              ; our application key | iv (44 bytes), then the client's
C_T0    equ 100             ; when our flight went out (0: its round trip has been taken)
C_RTO   equ 104             ; how long this connection's timer waits: a quarter of a
                            ;   second the first time, in units of 1/64 s (`tarm`)
C_SACK  equ 108             ; cursor at byte 24 of the client's unused AES-128 key half
                            ; (`C_KIV+44+16..31`), away from `C_T0` and `C_RTO`
TSLOT   equ 128
F_SACK  equ 1                ; C_FL2 bit 0: an application request arrived; the TLS SACK cursor is ready

; What 32-bit code calls pushad and popad: the seven registers of old besides rsp (so the
; one a routine returns is at [rsp+48] for eax, [rsp+24] for ebx, [rsp+16] for ebp,
; [rsp] for edi)
%macro pushad 0
        push rax
        push rcx
        push rdx
        push rbx
        push rbp
        push rsi
        push rdi
%endmacro
%macro popad 0
        pop rdi
        pop rsi
        pop rbp
        pop rbx
        pop rdx
        pop rcx
        pop rax
%endmacro
; HOT mask: the routine that follows begins where none of its jumps crosses a 32-byte
; boundary or ends on one. The routines a handshake spends its time in are placed so: on
; Intel's processors from Skylake to Cascade Lake (the cloud server's is one) such a jump
; is decoded again every time it is met, and so is all that shares its 32 bytes. Without
; this, how fast a handshake is there depends on how many bytes of code happen to lie in
; front (6% between two builds, measured). Bit k of the mask says that the routine may
; begin k bytes behind a boundary; it gets as few bytes of padding as take it to such a
; place (74 to 92 bytes in all, by what lies in front; when it was 35, the next boundary
; and some more for each would have been 226).
; `tools/jcc.py build/os.lst mask ROUTINE` says the mask, and the build says when
; a routine that was changed needs a new one. (Of `xdh` and `seal`, which are called
; once a handshake and once a record, the jumps inside loops count: ROUTINE:loops.)
%macro HOT 1
%assign %%k 32
%define %%pad 0
%rep 32
%assign %%k %%k - 1
%xdefine %%pad ((((%1) >> ((($ - $$) + %%k) & 31)) & 1) ? %%k : %%pad)
%endrep
        times %%pad nop
%endmacro
; JUMPH n, in front of a jump of n bytes where no routine begins (the ladder's step is
; calls one after another): the nop that keep it from crossing such a boundary, or
; ending on one.
%macro JUMPH 1
        times (((($ - $$) & 31) + %1) / 32) * (32 - (($ - $$) & 31)) nop
%endmacro
; Development builds (make DEBUG=1) count things in DBG and show six counters, four hex
; digits each, in place of the end of the page on port 80: `count n` adds one to counter n.
; 0: frames with a bad length or checksum, 1: cycles per frame handled (an average, made when
; shown), 2: connections refused for lack of room and frames lost to a full ring (`drain`),
; 3: segments that came early, 4: resends, 5: RSTs sent. With DEBUG=2, 3 and 5 are instead
; what tells how busy this processor is: the turns of its polling loop that found nothing to
; do, in units of 4,096, and the time, in units of 2^24 cycles. Two fetches give a rate, and
; a processor with nothing to do gives the rate that means idle (bench/busy.sh does that).
; With DEBUG=3 they are how often we asked for an address or to keep ours (`dhask`), and how
; often a server's yes was taken (`dhcp`): a lease that was renewed is one more of each.
DBG     equ BSS + 0x0F500
%macro count 1
%ifdef DEBUG
        inc dword [DBG + 4 * %1]
%endif
%endmacro
%ifndef DEBUG
%define tcpd tcp            ; (the polling loops call `tcp` through what counts its cycles)
%endif
%ifndef DHMAX
%define DHMAX 1 << 20       ; (make DHMAX=n, for a trial: no lease counts as longer than n s)
%endif
; WXGATE label (make WXTEST=6 or 7, for tools/wxtest.sh): what a table of interrupt handlers
; at address 0 would have for an invalid instruction, at 16 times its number: a gate to
; `label`, which is in our code. Then such an instruction. A processor that has no such
; table can't go on from there: the machine's end. (See `GDT`.)
%macro WXGATE 1
        mov dword [abs 6*16], ((0x100000 + DELTA + (%1 - mb)) & 0xFFFF) | 8 << 16
        mov dword [abs 6*16+4], 0x8E00 | ((0x100000 + DELTA + (%1 - mb)) >> 16 << 16)
        and qword [abs 6*16+8], 0
        ud2
%endmacro

; (make RACE=3 is in `find`.)
; RACEWAIT age (make RACE=n IDLE=1, for tools/racetest.py): `tqrun`, with a connection in
; hand that has been quiet for long enough to be taken (%1: its C_AGE as it was), stops
; there for up to 30 s, or until another processor has made the slot its own and has just
; taken that connection's first request: the moment at which going on as if the slot were
; still ours shows. RACE=1: before `tqrun` has said "in use" (`hold`), 2: after.
%macro RACEWAIT 1
        mov al, [NOW]
        sub al, %1
        cmp al, IDLE
        jbe %%go
        call clock
        mov r10d, eax
        xor r11d, r11d
%%w:    call bdrain
        pause
        call clock
        sub eax, r10d
        cmp eax, 30 * 2048
        jae %%go
        cmp dword [rbp+C_ST], 2
        jae %%two
        or r11d, -1             ; (below 2: it is another's, before its first request)
        jmp %%w
%%two:  test r11d, r11d
        jz %%w
%%go:
%endmacro

%ifdef HOST
BITS 64
        section .text align=32
        global sha256, hmac, expand, seal, seal_cached, shaconst, echost, xdh, sign
        global E, REGS
%else
        org 0x100000 + DELTA
BITS 32
mb:     dd 0x1BADB002, 0x00010002, -(0x1BADB002 + 0x00010002)
        dd mb, mb, 0, 0, start  ; (where this header is, where the image goes: there; all of it; where it is entered)

%include "start.asm"        ; `start`: from the loader to long mode, the page tables, the memory
%endif
; shaconst: SHA-256 constants from their definition: KT[i] = frac(cbrt(prime i)) * 2^32
; (Newton's method, so only exactly rounded x87 ops), HT[i] = frac(sqrt(prime i)) * 2^32.
; Inlined into the boot path; a function only in the host test build.
%ifdef HOST
shaconst:
        pushad
%endif
        mov edi, KT-4           ; the loop also counts 1 as a prime: its entry lands at KT-4
        push 3
        xor ebx, ebx            ; prime candidate
.np:    inc ebx
        mov ecx, ebx
.td:    dec ecx                 ; trial division by ebx-1 .. 2
        cmp ecx, 1
        jbe .pr
        mov eax, ebx
        cdq
        div ecx
        test edx, edx
        jnz .td
        jmp .np
.pr:    push rbx
        fild dword [rsp]        ; p
        fld st0                 ; y = p
        mov cl, 40
.nw:    fld st0
        fmul st0, st0
        fdivr st0, st2          ; p / y^2
        fadd st0, st1
        faddp st1, st0
        fidiv dword [rsp+8]     ; y = (2y + p/y^2) / 3
        loop .nw
        fmul dword [TWO32]
        fisttp qword [rdi]      ; low dword = fraction bits (the next entry overwrites the rest)
        fsqrt                   ; (only the first 8 matter; the rest land in junk space)
        fmul dword [TWO32]
        fisttp qword [rdi+HT-KT]
        pop rax
        scasd
        bt edi, 8               ; KT is 512-aligned: bit 8 first sets at KT+256
        jnc .np
        pop rax
%ifdef HOST
        popad
        ret
%else
%include "setup.asm"        ; `start`, on: what keys begin with, the card, the other processors

%include "poll.asm"         ; the polling loops, the rings, frames in and out of the card

%include "tcp.asm"          ; `tcp`: a frame that came, and what becomes of it

%include "ip6.asm"          ; `tcp6`, `nd`: the same over IPv6, and who our neighbours are

%include "send.asm"         ; `sendseg`, `sendrun`: the segments of a response

%include "request.asm"      ; `record`, `pick`, `seek`: a client's record and what it asks for

%include "timer.asm"        ; `tarm` to `clock`: who is owed something, and when

%include "conn.asm"         ; `find`, `prf`, `ckx`: whose connection a packet is; the SYN cookie

%include "seg.asm"          ; `respond`, `oohold`, `hsbuf`, `tcp_send`, `tcp_seg`, `csum`

%include "dhcp.asm"         ; `dhask`, `dhsend`, `dhcp`: our address, if the image has none

%include "tls.asm"          ; `handshake`: the ClientHello, and our flight
%endif

; Keep the standalone routine groups in this order to reduce padding before HOT entries.
%include "sha.asm"          ; `keys`, `sha256`, `hmac`, `expand`

%include "aesgcm.asm"       ; `seal`: AES-128-GCM

%include "curves.asm"       ; `xdh`, `sign`, `rand`, `stock`, and the arithmetic under them

%ifndef HOST
; Another processor starts here, in real mode (at TRAMP, where this is copied to: here it
; is never run): it takes a number, and with it the page tables made for it, and goes
; straight to long mode (`apstart`).
; It is the last of the code, and the one piece of it that need not be executable where
; it lies: so it is what the end of the last page with code falls into (the image is
; loaded where that comes true: DELTA), and everything behind its instructions, which
; is only read (the first of it: the few bytes this very code counts in and finds its
; segments by), begins in a page that cannot be executed.
BITS 16
tramp:  cli
        xor ax, ax
        mov ds, ax
        mov eax, 1
        lock xadd [TRAMP+apcount-tramp], eax
        inc eax
        cmp eax, MAXCPU
        jae .no
        shl eax, 15
        add eax, APMEM - 0x8000
        mov cr3, eax
        mov eax, cr4
        or eax, 0x220
        mov cr4, eax
        mov ecx, 0xC0000080
        rdmsr
        or ah, 9
        wrmsr
        mov eax, cr0
        and eax, 0x9FFFFFFF     ; (caches on: a processor starts with them off)
        or eax, 0x80010001
        mov cr0, eax
        o32 lgdt [TRAMP+apgdt-tramp]
        jmp dword 8:apstart
.no:    hlt
        jmp .no
xend:                           ; (the end of all instructions: see `codend`)
        times (tramp - $) & 3 db 0 ; (what `lock xadd` counts in lies on a multiple of 4 from
apcount: dd 0                   ; TRAMP, a page's start: never across two cache lines)
apgdt:  dw 23
        dd GDT
TRAMPLEN equ $ - tramp
BITS 64
%endif

; ----------------------------------------------------------------------------

codend:                          ; (what follows is only read: see the page tables in `start`)
%ifndef HOST
; CODEPG: the first page that has no code to be run: the one `xend` is in, the end of
; `tramp`'s instructions, which begins inside them: at most 63 bytes before `xend`, with
; the one DELTA that is a multiple of 64 below 4096. (If one of these lines fails, DELTA
; is not what the build would have found for this code.)
%ifndef SIZING
        times -(((DELTA + (xend - mb)) & 0xFFF) > 63) db 0
%endif
        times -((DELTA & 63) != 0 || DELTA >= 4096) db 0
        times -(xend - tramp < 63) db 0
%ifdef WXOPEN                   ; (make WXTEST=n WXOPEN=1, the control of tools/wxtest.sh: one
%ifndef WXTEST                  ; page more can be executed, the first of what is only read,
%error "WXOPEN is for tools/wxtest.sh (with WXTEST): it makes an image that is open" ; and
%endif                          ; what loaders left is left; what the test runs then runs)
CODEPG  equ ((0x100000 + DELTA + (xend - mb)) >> 12) + 1
%else
CODEPG  equ (0x100000 + DELTA + (xend - mb)) >> 12
%endif
%ifdef WXTEST
WXRET:  ret                     ; (make WXTEST=10)
%endif
%endif
TWO32:  dd 0x4F800000            ; 2^32 as a float

L_DER:  db 32, 7, "derived"
L_SHTS: db 32, 12, "s hs traffic"
L_SATS: db 32, 12, "s ap traffic"
L_CATS: db 32, 12, "c ap traffic"
L_FIN:  db 32, 8, "finished"
L_KEY:  db 16, 3, "key"
L_IV:   db 12, 2, "iv"
TLS13:  db "tls13 "

%ifndef HOST
CVCTX:  db "TLS 1.3, server CertificateVerify", 0
L_HRR:  db "HelloRetryRequest"
%include "regs.inc"
; The segments. Their table's first ten bytes, all zero, are also what every processor is
; given as its table of interrupt handlers (`start`, `apstart`): read as such a table's
; length and place they say "of length nothing". There are no handlers: whatever faults
; can't be delivered, nor can that, and the machine starts over. A processor that is not
; told so has the table the BIOS left it, or the one it is started up with: at address 0,
; which is where the frame in hand lies. A fault would then go where sixteen bytes of a
; client's packet say (tools/wxtest.sh, 6 and 7).
GDT:    dq 0                    ; (both marked as accessed: a processor that loads one not
        dq 0x00209B0000000000   ; 8: code, 64-bit      marked writes that mark, and this
        dq 0x0000930000000000   ; 16: data             table is in the image: not written)
GDTR:   dw 23
        dd GDT
%include "gen.inc"
H_AE:   db "*accept-encoding:"   ; header names as `seek` sees them, the line end in front
H_INM:  db "*if-none-match:"
T_BR:   db "br"
T_GZ:   db "gzip"
H_HOST: db "*host:"
%ifndef OURIP
DHHDR:  db 8, 0, 0x45, 0, 328 >> 8, 328 & 255, 0, 0, 0, 0 ; a DHCP message's frame from its type on
        db 64, 17, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255 ; (`dhsend`): IPv4, 328 bytes, UDP, to
        db 0, 68, 0, 67, 308 >> 8, 308 & 255, 0, 0 ; everybody; port 68 to 67, 308 bytes, no sum;
        db 1, 1, 6, 0           ; a request, from an Ethernet card (six bytes of address)
DHHLEN  equ $ - DHHDR
%endif
%ifdef OURIP6
IP6:    dq IP6A, IP6B           ; our IPv6 address (make IP6=...)
%endif
SYNOPT: db 2, 4, 1460 >> 8, 1460 & 255 ; maximum segment size: what fits an Ethernet frame
        db 1, 3, 3, 0           ; (padding,) window scale: ours is not shifted
SYNOPT_SACK: db 2, 4, 1460 >> 8, 1460 & 255, 4, 2, 1, 1
SYNOPT_BOTH: db 2, 4, 1460 >> 8, 1460 & 255, 4, 2, 1, 1, 1, 3, 3, 0
MSSTAB: dw 216, 536, 1220, 1440 ; the sizes we cut our segments to (the client's, rounded down)
SHTAIL: db 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
        db 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20
%else
%include "regs.inc"
%endif
%include "ec.inc"         ; curve programs
%ifndef HOST
        times -(DELTA + ($ - mb) > 0x10000) db 0 ; (the code must end below 1 MiB + 64 KiB: see LOW)
; The site: what tools/pack.py made of the folder that is served. A table of the paths,
; a table of the responses, and the responses themselves, as they are sent.
SITE:   incbin "site.bin"
%ifdef SIZING                   ; (the build's first look: so far from its start the image's
        dd xend - mb            ; instructions end, with `tramp`'s: see DELTA)
%endif
%endif
