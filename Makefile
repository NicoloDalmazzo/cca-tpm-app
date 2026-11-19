TARGETS = cca-tpm-relay is-realm

all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

install:
	for t in $(TARGETS); do \
		install -D -m 0755 $$t $(DESTDIR)/usr/bin/$$t; \
	done
