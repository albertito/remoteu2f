
all: libpam remoteu2f-cli/remoteu2f-cli remoteu2f-proxy/remoteu2f-proxy

libpam:
	$(MAKE) -C libpam

remoteu2f-cli/remoteu2f-cli:
	cd remoteu2f-cli && go build

remoteu2f-proxy/remoteu2f-proxy:
	cd remoteu2f-proxy && go build

clean:
	$(MAKE) -C libpam clean
	rm -f remoteu2f-cli/remoteu2f-cli
	rm -f remoteu2f-proxy/remoteu2f-proxy

.PHONY: all libpam clean
