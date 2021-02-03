/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvmi

#if !defined(_TRACE_KVMI_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVMI_H

#include <linux/tracepoint.h>

#ifndef __TRACE_KVMI_STRUCTURES
#define __TRACE_KVMI_STRUCTURES

#undef EN
#define EN(x) { x, #x }

static const struct trace_print_flags kvmi_msg_id_symbol[] = {
	EN(KVMI_EVENT),
	EN(KVMI_EVENT_REPLY),
	EN(KVMI_GET_VERSION),
	EN(KVMI_VM_CHECK_COMMAND),
	EN(KVMI_VM_CHECK_EVENT),
	EN(KVMI_VM_CONTROL_CMD_RESPONSE),
	EN(KVMI_VM_CONTROL_EVENTS),
	EN(KVMI_VM_CONTROL_SPP),
	EN(KVMI_VM_GET_INFO),
	EN(KVMI_VM_GET_MAP_TOKEN),
	EN(KVMI_VM_GET_MAX_GFN),
	EN(KVMI_VM_READ_PHYSICAL),
	EN(KVMI_VM_SET_PAGE_ACCESS),
	EN(KVMI_VM_SET_PAGE_SVE),
	EN(KVMI_VM_SET_PAGE_WRITE_BITMAP),
	EN(KVMI_VM_WRITE_PHYSICAL),
	EN(KVMI_VCPU_CONTROL_CR),
	EN(KVMI_VCPU_CONTROL_EPT_VIEW),
	EN(KVMI_VCPU_CONTROL_EVENTS),
	EN(KVMI_VCPU_CONTROL_MSR),
	EN(KVMI_VCPU_CONTROL_SINGLESTEP),
	EN(KVMI_VCPU_DISABLE_VE),
	EN(KVMI_VCPU_GET_CPUID),
	EN(KVMI_VCPU_GET_EPT_VIEW),
	EN(KVMI_VCPU_GET_INFO),
	EN(KVMI_VCPU_GET_MTRR_TYPE),
	EN(KVMI_VCPU_GET_REGISTERS),
	EN(KVMI_VCPU_GET_XSAVE),
	EN(KVMI_VCPU_INJECT_EXCEPTION),
	EN(KVMI_VCPU_PAUSE),
	EN(KVMI_VCPU_SET_EPT_VIEW),
	EN(KVMI_VCPU_SET_REGISTERS),
	EN(KVMI_VCPU_SET_VE_INFO),
	EN(KVMI_VCPU_TRANSLATE_GVA),
	EN(KVMI_VCPU_CHANGE_GFN),
	{-1, NULL}
};

static const struct trace_print_flags kvmi_descriptor_symbol[] = {
	EN(KVMI_DESC_IDTR),
	EN(KVMI_DESC_GDTR),
	EN(KVMI_DESC_LDTR),
	EN(KVMI_DESC_TR),
	{-1, NULL}
};

static const struct trace_print_flags kvmi_event_symbol[] = {
	EN(KVMI_EVENT_UNHOOK),
	EN(KVMI_EVENT_CMD_ERROR),
	EN(KVMI_EVENT_CR),
	EN(KVMI_EVENT_MSR),
	EN(KVMI_EVENT_XSETBV),
	EN(KVMI_EVENT_BREAKPOINT),
	EN(KVMI_EVENT_HYPERCALL),
	EN(KVMI_EVENT_PF),
	EN(KVMI_EVENT_TRAP),
	EN(KVMI_EVENT_DESCRIPTOR),
	EN(KVMI_EVENT_CREATE_VCPU),
	EN(KVMI_EVENT_PAUSE_VCPU),
	EN(KVMI_EVENT_SINGLESTEP),
	{ -1, NULL }
};

static const struct trace_print_flags kvmi_action_symbol[] = {
	{KVMI_EVENT_ACTION_CONTINUE, "continue"},
	{KVMI_EVENT_ACTION_RETRY, "retry"},
	{KVMI_EVENT_ACTION_CRASH, "crash"},
	{-1, NULL}
};

#endif /* __TRACE_KVMI_STRUCTURES */

TRACE_EVENT(
	kvmi_vm_command,
	TP_PROTO(__u16 id, __u32 seq),
	TP_ARGS(id, seq),
	TP_STRUCT__entry(
		__field(__u16, id)
		__field(__u32, seq)
	),
	TP_fast_assign(
		__entry->id = id;
		__entry->seq = seq;
	),
	TP_printk("%s seq %d",
		  trace_print_symbols_seq(p, __entry->id, kvmi_msg_id_symbol),
		  __entry->seq)
);

TRACE_EVENT(
	kvmi_vm_reply,
	TP_PROTO(__u16 id, __u32 seq, __s32 err),
	TP_ARGS(id, seq, err),
	TP_STRUCT__entry(
		__field(__u16, id)
		__field(__u32, seq)
		__field(__s32, err)
	),
	TP_fast_assign(
		__entry->id = id;
		__entry->seq = seq;
		__entry->err = err;
	),
	TP_printk("%s seq %d err %d",
		  trace_print_symbols_seq(p, __entry->id, kvmi_msg_id_symbol),
		  __entry->seq,
		  __entry->err)
);

TRACE_EVENT(
	kvmi_vcpu_command,
	TP_PROTO(__u16 vcpu, __u16 id, __u32 seq),
	TP_ARGS(vcpu, id, seq),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u16, id)
		__field(__u32, seq)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->id = id;
		__entry->seq = seq;
	),
	TP_printk("vcpu %d %s seq %d",
		  __entry->vcpu,
		  trace_print_symbols_seq(p, __entry->id, kvmi_msg_id_symbol),
		  __entry->seq)
);

TRACE_EVENT(
	kvmi_vcpu_reply,
	TP_PROTO(__u16 vcpu, __u16 id, __u32 seq, __s32 err),
	TP_ARGS(vcpu, id, seq, err),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u16, id)
		__field(__u32, seq)
		__field(__s32, err)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->id = id;
		__entry->seq = seq;
		__entry->err = err;
	),
	TP_printk("vcpu %d %s seq %d err %d",
		  __entry->vcpu,
		  trace_print_symbols_seq(p, __entry->id, kvmi_msg_id_symbol),
		  __entry->seq,
		  __entry->err)
);

TRACE_EVENT(
	kvmi_event,
	TP_PROTO(__u16 vcpu, __u32 id, __u32 seq),
	TP_ARGS(vcpu, id, seq),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u32, id)
		__field(__u32, seq)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->id = id;
		__entry->seq = seq;
	),
	TP_printk("vcpu %d %s seq %d",
		__entry->vcpu,
		trace_print_symbols_seq(p, __entry->id, kvmi_event_symbol),
		__entry->seq)
);

TRACE_EVENT(
	kvmi_event_reply,
	TP_PROTO(__u32 id, __u32 seq),
	TP_ARGS(id, seq),
	TP_STRUCT__entry(
		__field(__u32, id)
		__field(__u32, seq)
	),
	TP_fast_assign(
		__entry->id = id;
		__entry->seq = seq;
	),
	TP_printk("%s seq %d",
		trace_print_symbols_seq(p, __entry->id, kvmi_event_symbol),
		__entry->seq)
);

#define KVMI_ACCESS_PRINTK() ({						\
	const char *saved_ptr = trace_seq_buffer_ptr(p);		\
	static const char * const access_str[] = {			\
		"---", "r--", "-w-", "rw-", "--x", "r-x", "-wx", "rwx"	\
	};								\
	trace_seq_printf(p, "%s", access_str[__entry->access & 7]);	\
	saved_ptr;							\
})

TRACE_EVENT(
	kvmi_set_gfn_access,
	TP_PROTO(__u64 gfn, __u8 access, __u32 bitmap, __u16 slot),
	TP_ARGS(gfn, access, bitmap, slot),
	TP_STRUCT__entry(
		__field(__u64, gfn)
		__field(__u8, access)
		__field(__u32, bitmap)
		__field(__u16, slot)
	),
	TP_fast_assign(
		__entry->gfn = gfn;
		__entry->access = access;
		__entry->bitmap = bitmap;
		__entry->slot = slot;
	),
	TP_printk("gfn %llx %s write bitmap %x slot %d",
		  __entry->gfn, KVMI_ACCESS_PRINTK(),
		  __entry->bitmap, __entry->slot)
);

DECLARE_EVENT_CLASS(
	kvmi_event_send_template,
	TP_PROTO(__u16 vcpu),
	TP_ARGS(vcpu),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
	),
	TP_printk("vcpu %d",
		  __entry->vcpu
	)
);
DECLARE_EVENT_CLASS(
	kvmi_event_recv_template,
	TP_PROTO(__u16 vcpu, __u32 action),
	TP_ARGS(vcpu, action),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u32, action)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->action = action;
	),
	TP_printk("vcpu %d %s",
		  __entry->vcpu,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol)
	)
);

TRACE_EVENT(
	kvmi_event_cr_send,
	TP_PROTO(__u16 vcpu, __u32 cr, __u64 old_value, __u64 new_value),
	TP_ARGS(vcpu, cr, old_value, new_value),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u32, cr)
		__field(__u64, old_value)
		__field(__u64, new_value)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->cr = cr;
		__entry->old_value = old_value;
		__entry->new_value = new_value;
	),
	TP_printk("vcpu %d cr %x old_value %llx new_value %llx",
		  __entry->vcpu,
		  __entry->cr,
		  __entry->old_value,
		  __entry->new_value
	)
);
TRACE_EVENT(
	kvmi_event_cr_recv,
	TP_PROTO(__u16 vcpu, __u32 action, __u64 new_value),
	TP_ARGS(vcpu, action, new_value),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u32, action)
		__field(__u64, new_value)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->action = action;
		__entry->new_value = new_value;
	),
	TP_printk("vcpu %d %s new_value %llx",
		  __entry->vcpu,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol),
		  __entry->new_value
	)
);

TRACE_EVENT(
	kvmi_event_msr_send,
	TP_PROTO(__u16 vcpu, __u32 msr, __u64 old_value, __u64 new_value),
	TP_ARGS(vcpu, msr, old_value, new_value),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u32, msr)
		__field(__u64, old_value)
		__field(__u64, new_value)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->msr = msr;
		__entry->old_value = old_value;
		__entry->new_value = new_value;
	),
	TP_printk("vcpu %d msr %x old_value %llx new_value %llx",
		  __entry->vcpu,
		  __entry->msr,
		  __entry->old_value,
		  __entry->new_value
	)
);
TRACE_EVENT(
	kvmi_event_msr_recv,
	TP_PROTO(__u16 vcpu, __u32 action, __u64 new_value),
	TP_ARGS(vcpu, action, new_value),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u32, action)
		__field(__u64, new_value)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->action = action;
		__entry->new_value = new_value;
	),
	TP_printk("vcpu %d %s new_value %llx",
		  __entry->vcpu,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol),
		  __entry->new_value
	)
);

DEFINE_EVENT(kvmi_event_send_template, kvmi_event_xsetbv_send,
	TP_PROTO(__u16 vcpu),
	TP_ARGS(vcpu)
);
DEFINE_EVENT(kvmi_event_recv_template, kvmi_event_xsetbv_recv,
	TP_PROTO(__u16 vcpu, __u32 action),
	TP_ARGS(vcpu, action)
);

TRACE_EVENT(
	kvmi_event_bp_send,
	TP_PROTO(__u16 vcpu, __u64 gpa, __u64 old_rip),
	TP_ARGS(vcpu, gpa, old_rip),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u64, gpa)
		__field(__u64, old_rip)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->gpa = gpa;
		__entry->old_rip = old_rip;
	),
	TP_printk("vcpu %d gpa %llx rip %llx",
		  __entry->vcpu,
		  __entry->gpa,
		  __entry->old_rip
	)
);
TRACE_EVENT(
	kvmi_event_bp_recv,
	TP_PROTO(__u16 vcpu, __u32 action, __u64 new_rip),
	TP_ARGS(vcpu, action, new_rip),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u32, action)
		__field(__u64, new_rip)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->action = action;
		__entry->new_rip = new_rip;
	),
	TP_printk("vcpu %d %s rip %llx",
		  __entry->vcpu,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol),
		  __entry->new_rip
	)
);

DEFINE_EVENT(kvmi_event_send_template, kvmi_event_hc_send,
	TP_PROTO(__u16 vcpu),
	TP_ARGS(vcpu)
);
DEFINE_EVENT(kvmi_event_recv_template, kvmi_event_hc_recv,
	TP_PROTO(__u16 vcpu, __u32 action),
	TP_ARGS(vcpu, action)
);

TRACE_EVENT(
	kvmi_event_pf_send,
	TP_PROTO(__u16 vcpu, __u64 gpa, __u64 gva, __u8 access, __u64 rip),
	TP_ARGS(vcpu, gpa, gva, access, rip),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u64, gpa)
		__field(__u64, gva)
		__field(__u8, access)
		__field(__u64, rip)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->gpa = gpa;
		__entry->gva = gva;
		__entry->access = access;
		__entry->rip = rip;
	),
	TP_printk("vcpu %d gpa %llx %s gva %llx rip %llx",
		  __entry->vcpu,
		  __entry->gpa,
		  KVMI_ACCESS_PRINTK(),
		  __entry->gva,
		  __entry->rip
	)
);
TRACE_EVENT(
	kvmi_event_pf_recv,
	TP_PROTO(__u16 vcpu, __u32 action, __u64 next_rip, size_t custom_size,
		 bool singlestep, bool ret),
	TP_ARGS(vcpu, action, next_rip, custom_size, singlestep, ret),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u32, action)
		__field(__u64, next_rip)
		__field(size_t, custom_size)
		__field(bool, singlestep)
		__field(bool, ret)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->action = action;
		__entry->next_rip = next_rip;
		__entry->custom_size = custom_size;
		__entry->singlestep = singlestep;
		__entry->ret = ret;
	),
	TP_printk("vcpu %d %s rip %llx custom_size %zu %s",
		  __entry->vcpu,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol),
		  __entry->next_rip, __entry->custom_size,
		  (__entry->singlestep ? (__entry->ret ? "singlestep failed" :
							 "singlestep running")
					: "")
	)
);

#define EXS(x) { x##_VECTOR, "#" #x }

#define kvm_trace_sym_exc						\
	EXS(DE), EXS(DB), EXS(BP), EXS(OF), EXS(BR), EXS(UD), EXS(NM),	\
	EXS(DF), EXS(TS), EXS(NP), EXS(SS), EXS(GP), EXS(PF),		\
	EXS(MF), EXS(AC), EXS(MC)

DECLARE_EVENT_CLASS(
	kvmi_exception_template,
	TP_PROTO(struct kvm_vcpu *vcpu),
	TP_ARGS(vcpu),
	TP_STRUCT__entry(
		__field(__u16, vcpu_id)
		__field(__u8, vector)
		__field(__u64, address)
		__field(__u16, error_code)
		__field(bool, error_code_valid)
	),
	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->vector = VCPUI(vcpu)->exception.nr;
		__entry->address = VCPUI(vcpu)->exception.address;
		__entry->error_code = VCPUI(vcpu)->exception.error_code;
		__entry->error_code_valid =
			VCPUI(vcpu)->exception.error_code_valid;
	),
	TP_printk("vcpu %d %s address %llx error %x",
		  __entry->vcpu_id,
		  __print_symbolic(__entry->vector, kvm_trace_sym_exc),
		  __entry->vector == PF_VECTOR ? __entry->address : 0,
		  __entry->error_code_valid ? __entry->error_code : 0
	)
);

DEFINE_EVENT(kvmi_exception_template, kvmi_cmd_inject_exception,
	TP_PROTO(struct kvm_vcpu *vcpu),
	TP_ARGS(vcpu)
);

DEFINE_EVENT(kvmi_exception_template, kvmi_event_trap_send,
	TP_PROTO(struct kvm_vcpu *vcpu),
	TP_ARGS(vcpu)
);
DEFINE_EVENT(kvmi_event_recv_template, kvmi_event_trap_recv,
	TP_PROTO(__u16 vcpu, __u32 action),
	TP_ARGS(vcpu, action)
);

TRACE_EVENT(
	kvmi_event_desc_send,
	TP_PROTO(__u16 vcpu, __u8 descriptor, __u8 write),
	TP_ARGS(vcpu, descriptor, write),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u8, descriptor)
		__field(__u8, write)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->descriptor = descriptor;
		__entry->write = write;
	),
	TP_printk("vcpu %d %s %s",
		  __entry->vcpu,
		  __entry->write ? "write" : "read",
		  trace_print_symbols_seq(p, __entry->descriptor,
					  kvmi_descriptor_symbol)
	)
);
DEFINE_EVENT(kvmi_event_recv_template, kvmi_event_desc_recv,
	TP_PROTO(__u16 vcpu, __u32 action),
	TP_ARGS(vcpu, action)
);

DEFINE_EVENT(kvmi_event_send_template, kvmi_event_create_vcpu_send,
	TP_PROTO(__u16 vcpu),
	TP_ARGS(vcpu)
);
DEFINE_EVENT(kvmi_event_recv_template, kvmi_event_create_vcpu_recv,
	TP_PROTO(__u16 vcpu, __u32 action),
	TP_ARGS(vcpu, action)
);

DEFINE_EVENT(kvmi_event_send_template, kvmi_event_pause_vcpu_send,
	TP_PROTO(__u16 vcpu),
	TP_ARGS(vcpu)
);
DEFINE_EVENT(kvmi_event_recv_template, kvmi_event_pause_vcpu_recv,
	TP_PROTO(__u16 vcpu, __u32 action),
	TP_ARGS(vcpu, action)
);

DEFINE_EVENT(kvmi_event_send_template, kvmi_event_singlestep_send,
	TP_PROTO(__u16 vcpu),
	TP_ARGS(vcpu)
);
DEFINE_EVENT(kvmi_event_recv_template, kvmi_event_singlestep_recv,
	TP_PROTO(__u16 vcpu, __u32 action),
	TP_ARGS(vcpu, action)
);

TRACE_EVENT(
	kvmi_run_singlestep,
	TP_PROTO(struct kvm_vcpu *vcpu, __u64 gpa, __u8 access, __u8 level,
		 size_t custom_size),
	TP_ARGS(vcpu, gpa, access, level, custom_size),
	TP_STRUCT__entry(
		__field(__u16, vcpu_id)
		__field(__u64, gpa)
		__field(__u8, access)
		__field(size_t, len)
		__array(__u8, insn, 15)
		__field(__u8, level)
		__field(size_t, custom_size)
	),
	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->gpa = gpa;
		__entry->access = access;
		__entry->len = min_t(size_t, 15,
				     vcpu->arch.emulate_ctxt.fetch.ptr
				     - vcpu->arch.emulate_ctxt.fetch.data);
		memcpy(__entry->insn, vcpu->arch.emulate_ctxt.fetch.data, 15);
		__entry->level = level;
		__entry->custom_size = custom_size;
	),
	TP_printk("vcpu %d gpa %llx %s insn %s level %x custom_size %zu",
		  __entry->vcpu_id,
		  __entry->gpa,
		  KVMI_ACCESS_PRINTK(),
		  __print_hex(__entry->insn, __entry->len),
		  __entry->level,
		  __entry->custom_size
	)
);

TRACE_EVENT(
	kvmi_stop_singlestep,
	TP_PROTO(__u16 vcpu),
	TP_ARGS(vcpu),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
	),
	TP_printk("vcpu %d", __entry->vcpu
	)
);

TRACE_EVENT(
	kvmi_mem_map,
	TP_PROTO(struct kvm *kvm, gpa_t req_gpa, gpa_t map_gpa),
	TP_ARGS(kvm, req_gpa, map_gpa),
	TP_STRUCT__entry(
		__field_struct(uuid_t, uuid)
		__field(gpa_t, req_gpa)
		__field(gpa_t, map_gpa)
	),
	TP_fast_assign(
		struct kvm_introspection *kvmi = kvmi_get(kvm);

		if (kvmi) {
			memcpy(&__entry->uuid, &kvmi->uuid, sizeof(uuid_t));
			kvmi_put(kvm);
		} else
			memset(&__entry->uuid, 0, sizeof(uuid_t));
		__entry->req_gpa = req_gpa;
		__entry->map_gpa = map_gpa;
	),
	TP_printk("vm %pU req_gpa %llx map_gpa %llx",
		&__entry->uuid,
		__entry->req_gpa,
		__entry->map_gpa
	)
);

TRACE_EVENT(
	kvmi_mem_unmap,
	TP_PROTO(gpa_t map_gpa),
	TP_ARGS(map_gpa),
	TP_STRUCT__entry(
		__field(gpa_t, map_gpa)
	),
	TP_fast_assign(
		__entry->map_gpa = map_gpa;
	),
	TP_printk("map_gpa %llx",
		__entry->map_gpa
	)
);

#endif /* _TRACE_KVMI_H */

#include <trace/define_trace.h>
