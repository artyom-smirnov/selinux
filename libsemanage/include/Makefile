# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCDIR ?= $(PREFIX)/include/semanage

all:

install: all
	test -d $(INCDIR) || install -m 755 -d $(INCDIR)
	install -m 644 $(wildcard semanage/*.h) $(INCDIR)
	test -d $(INCDIR)/private || install -m 755 -d $(INCDIR)/private
	install -m 644 $(wildcard semanage/private/*.h) $(INCDIR)/private

indent:
	../../scripts/Lindent $(wildcard semanage/*.h)
	../../scripts/Lindent $(wildcard semanage/private/*.h)
