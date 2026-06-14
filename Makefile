RELAYS := ap-host claude-client imapsmtp-client rss-client smtp-host

.PHONY: all clean $(RELAYS)

all: biset $(RELAYS)

biset:
	go build -o biset .

$(RELAYS):
	go build -o relays/$@/biset-$@ ./relays/$@

clean:
	rm -f biset
	$(foreach r,$(RELAYS),rm -f relays/$(r)/biset-$(r);)
