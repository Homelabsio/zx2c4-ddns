PKG_CONFIG ?= pkg-config
PREFIX ?= /usr
DESTDIR ?=
SYSCONFDIR ?= /etc
BINDIR ?= $(PREFIX)/bin
SYSTEMDUNITDIR ?= $(shell $(PKG_CONFIG) --variable=systemdsystemunitdir systemd 2>/dev/null || echo "$(PREFIX)/lib/systemd/system")

all: ddns

ddns: $(wildcard  *.go) go.mod
	GOOS=linux CGO_ENABLED=0 go build -o $@ -v

ddns.service: ddns.service.in
	sed -e 's^BINDIR^$(BINDIR)^g' -e 's^SYSCONFDIR^$(SYSCONFDIR)^g' $< > $@

install: ddns ddns.service ddns.socket ddns.conf
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 ddns "$(DESTDIR)$(BINDIR)/ddns"
	@install -v -d "$(DESTDIR)$(SYSTEMDUNITDIR)" && install -v -m 0644 ddns.service ddns.socket "$(DESTDIR)$(SYSTEMDUNITDIR)/"
	@install -v -d "$(DESTDIR)$(SYSCONFDIR)" && install -v -m 0600 ddns.conf "$(DESTDIR)$(SYSCONFDIR)/"

clean:
	@rm -vf ddns ddns.service

.PHONY: clean all install
