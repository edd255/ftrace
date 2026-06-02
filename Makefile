CC := gcc
CFLAGS ?= -O2 -fstack-protector-strong -fPIE -fstack-clash-protection -fcf-protection=full -Wformat -Wformat-security
CPPFLAGS ?= -D_FORTIFY_SOURCE=3
LDFLAGS ?= -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -s
LDLIBS ?= -lcapstone

DEPS := functools.h readelf.h ptrace.h logging.h

.PHONY: clean

ftrace: ftrace.c $(DEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o ftrace ftrace.c $(LDLIBS)

test: test.c
	$(CC) -o test test.c

clean:
	rm -f ftrace test
