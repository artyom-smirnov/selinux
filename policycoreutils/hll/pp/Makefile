# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCLUDEDIR ?= $(PREFIX)/include
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
LIBDIR ?= $(PREFIX)/lib
LIBEXECDIR ?= $(PREFIX)/libexec
HLLDIR ?= $(LIBEXECDIR)/selinux/hll

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -I$(INCLUDEDIR)
LDLIBS = $(LIBDIR)/libsepol.a -L$(LIBDIR)
PP_OBJS = pp.o

all: pp

pp: $(PP_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: all
	-mkdir -p $(HLLDIR)
	install -m 755 pp $(HLLDIR)

relabel:

clean:
	-rm -f pp *.o

indent:
	../../scripts/Lindent $(wildcard *.[ch])
