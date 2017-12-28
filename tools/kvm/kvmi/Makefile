HOST   := host
SVA    := sva
TOPDIR := ../../..
CO     := -g -pthread -I./include
CO_LIB := $(CO) -fPIC -DPIC
LO_LIB := -shared -Wl,-version-script=version

kvmi-test : kvmi-test.c $(HOST)/libkvmi.so $(SVA)/libkvmi.so
	$(CC) $(CO) -o $@ kvmi-test.c -L$(HOST) -lkvmi 

%/libkvmi.so : libkvmi.c
	$(CC) $(CO_LIB) $(CFLAGS) $(LO_LIB) -o $@ libkvmi.c

$(HOST)/libkvmi.so : CFLAGS := -DUSE_UNIX_SOCKET

$(HOST)/libkvmi.so : host
$(SVA)/libkvmi.so : sva

libkvmi.c : include/linux/kvmi.h include/asm/kvmi.h
include/linux/kvmi.h : include/linux/kvm_para.h
include/asm/kvmi.h : include/asm/kvm.h

include/linux/% :
	install -Dm0644 $(TOPDIR)/include/uapi/linux/$* $@

include/asm/% :
	install -Dm0644 $(TOPDIR)/arch/x86/include/uapi/asm/$* $@

host sva :
	mkdir $@

.PHONY : clean
clean :
	-rm kvmi-test $(HOST)/libkvmi.so $(SVA)/libkvmi.so

