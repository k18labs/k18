# B: where generated files go. CERT: the server's identity (see tools/gen.py). Both can be
# set to build a second image, e.g. `make B=build-real CERT=cert-real`.
# IP: the address the server answers on, if the image is to have one of its own. Without it
# (the default) the image asks for its address where it boots (DHCP), and is not tied to a
# machine. For a real server: `make B=build-hz CERT=cert-hz NAME=<name or IP in the certificate>`.
B ?= build
CERT ?= cert
IP ?=
OURIP := $(if $(IP),-DOURIP=$(shell python3 -c 'import ipaddress; print("0x" + ipaddress.IPv4Address("$(IP)").packed[::-1].hex())'),)
# IP6: an IPv6 address for the image as well (it is not asked for anywhere: a host says
# which one a machine has). Without it the image has no IPv6 in it.
IP6 ?=
OURIP6 := $(if $(IP6),$(shell python3 -c 'import ipaddress; b = ipaddress.IPv6Address("$(IP6)").packed; print("-DIP6A=0x%016x -DIP6B=0x%016x" % (int.from_bytes(b[:8], "little"), int.from_bytes(b[8:], "little")))'),)
# CAP=n (tests): no more than n slots in each connection table, however much memory there is.
# IDLE=n (tests): how long a connection must have been quiet to be replaced when there is no room
# TSHARE=n: the table of TLS connections gets 1/2^n of the memory (default 3: an eighth), the
# table of port 80 connections the rest
CAP ?=
IDLE ?=
TSHARE ?=
TABLEDEF := $(if $(CAP),-DCAP=$(CAP),) $(if $(IDLE),-DIDLE=$(IDLE),) $(if $(TSHARE),-DTSHARE=$(TSHARE),)
# DEBUG=1 (development): count dropped and resent packets, shown in the page on port 80
# (DEBUG=2: and how busy each processor is, see bench/busy.sh; DEBUG=3: and what was
# asked of DHCP and answered with a yes)
# DHMAX=n (a trial): a DHCP lease counts as n seconds at most, so it is renewed after n/2
# LIFE=n (development): the machine is reset after about n minutes (at 2.1 GHz), come what may
DEBUGDEF := $(if $(DEBUG),-DDEBUG=$(DEBUG),) $(if $(LIFE),-DLIFE=$(LIFE),) $(if $(DHMAX),-DDHMAX=$(DHMAX),)
# SITE: the folder of files that is served (tools/pack.py makes them part of the image).
# P80=redirect: port 80 sends everybody to https://NAME/ (default: it serves the page at /)
# HSTS=seconds, CACHE=seconds, HEADERS='Name: value': headers for every file (tools/pack.py)
# COMPRESS=0: no file is also packed compressed
SITE ?= www
P80 ?= page
HSTS ?=
CACHE ?= 600
HEADERS ?=
COMPRESS ?= 1
# (they reach tools/pack.py and tools/made.py by way of the environment, as they are: a
# header's quotes are a header's, and no shell reads them)
export P80 HSTS CACHE HEADERS COMPRESS
# WIN=n: so many segments of a response may be on their way to a client at once
# NOTSO=1 (tests): a segment a frame, also where the card would cut frames into segments
# BIGSH=n (tests): each processor has 2^n buffers for the frames the card cuts up (default 3)
# RACE=n (tests): the timer stops in the middle of a connection it has in hand (tools/racetest.py)
WIN ?=
WINDEF := $(if $(WIN),-DWIN=$(WIN),) $(if $(WXTEST),-DWXTEST=$(WXTEST),) $(if $(WXOPEN),-DWXOPEN,) $(if $(WXPAD),-DWXPAD,) $(if $(ISNTOP),-DISNTOP=$(ISNTOP),) $(if $(ISNBITS),-DISNBITS=$(ISNBITS),) $(if $(KEYLIFE),-DKEYLIFE=$(KEYLIFE),) $(if $(STLIFE),-DSTLIFE=$(STLIFE),) $(if $(NOTSO),-DNOTSO,) $(if $(BIGSH),-DBIGSH=$(BIGSH),) $(if $(RACE),-DRACE=$(RACE),)

# the routines a handshake spends its time in: none of their jumps may lie on a 32-byte
# boundary (tools/jcc.py; of `xdh` and `seal` the jumps inside loops)
HOT := shablk xdh:loops cswap comb select vm fas fmul fsqr fmul1 inv seal:loops ks64 gh1 aeskey aes4

# (the image, its listing and the disk hold the private key, and so does the tests' object
# and what is linked with it: for their owner's eyes only from the moment they are made
# (umask 077), and if they were there before (chmod))
# The image: hand-written assembly (src/os.asm) -> flat binary, loaded at 1 MiB and a few
# bytes (DELTA, below); and a disk image that boots it (tools/mkdisk.py): the boot sector
# (src/boot.asm, for a BIOS), then a partition with the image in it, and what UEFI
# firmware starts (src/efi.asm). os.asm includes the other files of src/, a subsystem
# each: one unit for the assembler.
OS := $(filter-out src/boot.asm src/efi.asm,$(wildcard src/*.asm))
all: $(B)/disk.img

$(B)/ip: FORCE
	@mkdir -p $(B)
	@printf '%s' '$(IP)' > $@.$$$$; if cmp -s $@.$$$$ $@; then rm $@.$$$$; else mv $@.$$$$ $@; fi
$(B)/ip6: FORCE
	@mkdir -p $(B)
	@printf '%s' '$(IP6)' > $@.$$$$; if cmp -s $@.$$$$ $@; then rm $@.$$$$; else mv $@.$$$$ $@; fi
FORCE:

$(B)/disk.img: src/boot.asm src/efi.asm $(B)/os.bin tools/mkdisk.py
	nasm -f bin -o $(B)/boot.bin src/boot.asm
	nasm -f bin -o $(B)/efi.bin src/efi.asm
	umask 077; python3 tools/mkdisk.py $(B)/boot.bin $(B)/efi.bin $(B)/os.bin $@
	@chmod go= $@

# cert/ is made on the first build (a private CA and a leaf) or holds a real certificate.
# NAME: the name a generated certificate is for, and the one of a certificate's names
# that port 80 sends everybody to (default: the certificate's first). SAN='a b': further
# names for a generated certificate. $(B)/names.conf changes when they do.
# (A NAME from the environment that is this machine's own name is not meant for us: WSL
# exports that to every shell, and the first build would make its certificate for it.)
ifeq ($(origin NAME),environment)
ifeq ($(NAME),$(shell hostname))
NAME :=
endif
endif
# KEYLESS=1: the image without its key, made from the certificates alone ($(CERT) needs
# no server.key): the same bytes as the one that has the key, but for the key's 32. For
# comparing (tools/repro.sh; $(B)/made says what an image is without its key): it cannot sign.
KEYLESS ?=
GEN := $(B)/gen.inc $(B)/ec.inc $(B)/step.inc $(B)/regs.inc $(B)/conf.inc
ID := $(if $(KEYLESS),,$(CERT)/server.key) $(CERT)/server.pem
$(ID) &:
	@mkdir -p $(B)
	KEYLESS=$(KEYLESS) CERT=$(CERT) python3 tools/gen.py $(B)

$(B)/names.conf: FORCE
	@mkdir -p $(B)
	@echo '$(NAME) $(SAN)' > $@.$$$$; if cmp -s $@.$$$$ $@; then rm $@.$$$$; else mv $@.$$$$ $@; fi

$(GEN) &: tools/gen.py tools/ec.py $(ID) $(B)/names.conf
	@mkdir -p $(B)
	KEYLESS=$(KEYLESS) CERT=$(CERT) python3 tools/gen.py $(B)

# The site: every file under $(SITE) as the response it is sent as, and the table of paths.
# It is made again when $(B)/site.conf changes, which lists the settings and the files
# (names, sizes, times: file names are not for make to read).
PACKED := $(B)/site.inc $(B)/site.bin
$(B)/site.conf: FORCE
	@mkdir -p $(B)
	@{ printf '%s\n' '$(SITE)' "$$P80" "$$HSTS" "$$CACHE" "$$HEADERS" "$$COMPRESS"; find $(SITE) -type f -printf '%p %s %T@\n' | sort; } > $@.$$$$; \
	 if cmp -s $@.$$$$ $@; then rm $@.$$$$; else mv $@.$$$$ $@; fi
$(PACKED) &: tools/pack.py $(B)/site.conf $(GEN)
	python3 tools/pack.py $(SITE) $(B)

# It is assembled twice. Memory is barred from execution a page at a time, so the image's
# code has to end where a page ends, and nothing is padded for that: the image is loaded
# DELTA bytes above 1 MiB instead (its header says where). The first time says where the
# code ends (-DSIZING: the last four bytes of $(B)/os.sizing, which is then emptied: it
# is an image, key and all), DELTA is what puts a page boundary there, a multiple of
# 64, and the second time is the image. (src/os.asm, `codend`, refuses any other DELTA.)
ASDEF := $(OURIP) $(OURIP6) $(TABLEDEF) $(DEBUGDEF) $(WINDEF)
$(B)/os.bin: $(OS) $(GEN) $(PACKED) $(B)/ip $(B)/ip6
	@umask 077; nasm -f bin $(ASDEF) -DSIZING -I$(B)/ -Isrc/ -o $(B)/os.sizing src/os.asm
	@echo "-DDELTA=$$(( (4096 - $$(tail -c 4 $(B)/os.sizing | od -An -tu4) / 64 * 64 % 4096) % 4096 ))" > $(B)/delta; : > $(B)/os.sizing
	umask 077; nasm -f bin $(ASDEF) $$(cat $(B)/delta) -I$(B)/ -Isrc/ -o $@ -l $(B)/os.lst src/os.asm
	@chmod go= $@ $(B)/os.lst
	@python3 tools/made.py $(B) $(ASDEF) $$(cat $(B)/delta)
	@echo "image: $$(stat -c %s $@) bytes, of which the site: $$(stat -c %s $(B)/site.bin)"
	@python3 tools/jcc.py $(B)/os.lst $(HOT) || echo "(these jumps lie on 32-byte boundaries: see HOT in src/os.asm)"

# asm crypto checked against pyca/cryptography on the host (the asm calls and pushes as it
# likes: no red zone; and it wants its buffers below 4 GiB: no PIE)
HOSTCC := gcc -no-pie -fno-pie -O1 -mno-red-zone
$(B)/test_asm: test/test_asm.c test/asm.h $(OS) $(GEN)
	umask 077; nasm -f elf64 -DHOST -I$(B)/ -Isrc/ -o $(B)/os_host.o src/os.asm
	umask 077; $(HOSTCC) -o $@ test/test_asm.c $(B)/os_host.o
	@chmod go= $@ $(B)/os_host.o

test: $(B)/test_asm
	python3 tools/ec.py
	CERT=$(CERT) python3 test/test_crypto.py $(B)/test_asm

# The same object against what others have made (tools/outside.sh fetch gets it into ext/):
# Wycheproof's vectors and RFC 6979's (test/outside.py), and under Valgrind with every
# secret marked undefined, so that a jump or an address made of one is an error
# (test/ct.c; the runs after the first are the controls: each has one, which must be found)
EXT ?= ext
VG := VALGRIND_LIB=$(EXT)/valgrind/usr/libexec/valgrind $(EXT)/valgrind/usr/bin/valgrind -q --error-exitcode=9
outside: $(B)/test_asm
	CERT=$(CERT) python3 -I test/outside.py $(B)/test_asm $(EXT)/wycheproof/testvectors_v1
$(B)/ct: test/ct.c test/asm.h $(B)/test_asm
	umask 077; $(HOSTCC) -I$(EXT)/valgrind/usr/include -o $@ test/ct.c $(B)/os_host.o
	@chmod go= $@
ct: $(B)/ct
	$(VG) $(B)/ct
	@for n in 1 2 3 4 5 6; do if $(VG) $(B)/ct $$n >/dev/null 2>&1; then echo "FAIL: control $$n went unnoticed"; exit 1; fi; done
	@echo "ok   nothing jumps on or indexes with a secret (and each of six controls that does is noticed)"

# what the curve and hash code cost natively (the same object the tests use, timed on this host)
bench: $(B)/test_asm test/bench.c
	umask 077; $(HOSTCC) -o $(B)/bench_asm test/bench.c $(B)/os_host.o
	@chmod go= $(B)/bench_asm
	$(B)/bench_asm

.PHONY: all test outside ct bench FORCE
