#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>

int do_insn_fetch_bytes(struct x86_emulate_ctxt *ctxt,
                           unsigned size);
