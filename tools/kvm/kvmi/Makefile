TOPDIR := ../../..
CO     := -g -pthread -I./include
CO_LIB := $(CO) -fPIC -DPIC
LO_LIB := -shared -Wl,-version-script=version
DESTDIR := /usr/local

kvmi-test : kvmi-test.c libkvmi.so
	$(CC) $(CO) -o $@ kvmi-test.c -L. -lkvmi

libkvmi.so : libkvmi.c version
	$(CC) $(CO_LIB) $(LO_LIB) -o $@ libkvmi.c

libkvmi.c : include/linux/kvmi.h include/asm/kvmi.h
include/linux/kvmi.h : include/linux/kvm_para.h
include/asm/kvmi.h : include/asm/kvm.h

include/linux/kvm_para.h :
	install -Dm0644 $(TOPDIR)/include/uapi/linux/$(notdir $@) $@

include/asm/kvm.h :
	install -Dm0644 $(TOPDIR)/arch/x86/include/uapi/asm/$(notdir $@) $@

.PHONY : clean
clean :
	-rm kvmi-test libkvmi.so include/asm/kvm.h include/linux/kvm_para.h

.PHONY : install
install: libkvmi.so
	cp -rv include/ $(DESTDIR)
	cp libkvmi.so $(DESTDIR)/lib
