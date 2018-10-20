TARGET		?= parasite

obj-m		:= $(TARGET).o
$(TARGET)-y	+= main.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD clean
