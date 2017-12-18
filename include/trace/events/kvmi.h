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
	EN(KVMI_GET_VERSION),
	EN(KVMI_PAUSE_VCPU),
	EN(KVMI_GET_GUEST_INFO),
	EN(KVMI_GET_REGISTERS),
	EN(KVMI_SET_REGISTERS),
	EN(KVMI_GET_PAGE_ACCESS),
	EN(KVMI_SET_PAGE_ACCESS),
	EN(KVMI_INJECT_EXCEPTION),
	EN(KVMI_READ_PHYSICAL),
	EN(KVMI_WRITE_PHYSICAL),
	EN(KVMI_GET_MAP_TOKEN),
	EN(KVMI_CONTROL_EVENTS),
	EN(KVMI_CONTROL_CR),
	EN(KVMI_CONTROL_MSR),
	EN(KVMI_EVENT),
	EN(KVMI_EVENT_REPLY),
	EN(KVMI_GET_CPUID),
	EN(KVMI_GET_XSAVE),
	{-1, NULL}
};

static const struct trace_print_flags kvmi_event_id_symbol[] = {
	EN(KVMI_EVENT_CR),
	EN(KVMI_EVENT_MSR),
	EN(KVMI_EVENT_XSETBV),
	EN(KVMI_EVENT_BREAKPOINT),
	EN(KVMI_EVENT_HYPERCALL),
	EN(KVMI_EVENT_PAGE_FAULT),
	EN(KVMI_EVENT_TRAP),
	EN(KVMI_EVENT_DESCRIPTOR),
	EN(KVMI_EVENT_CREATE_VCPU),
	EN(KVMI_EVENT_PAUSE_VCPU),
	{-1, NULL}
};

static const struct trace_print_flags kvmi_descriptor_symbol[] = {
	EN(KVMI_DESC_IDTR),
	EN(KVMI_DESC_GDTR),
	EN(KVMI_DESC_LDTR),
	EN(KVMI_DESC_TR),
	{-1, NULL}
};

static const struct trace_print_flags kvmi_action_symbol[] = {
	{KVMI_EVENT_ACTION_CONTINUE, "continue"},
	{KVMI_EVENT_ACTION_RETRY, "retry"},
	{KVMI_EVENT_ACTION_CRASH, "crash"},
	{-1, NULL}
};

#endif /* __TRACE_KVMI_STRUCTURES */

TRACE_EVENT(
	kvmi_msg_dispatch,
	TP_PROTO(__u16 id, __u16 size),
	TP_ARGS(id, size),
	TP_STRUCT__entry(
		__field(__u16, id)
		__field(__u16, size)
	),
	TP_fast_assign(
		__entry->id = id;
		__entry->size = size;
	),
	TP_printk("%s size %u",
		  trace_print_symbols_seq(p, __entry->id, kvmi_msg_id_symbol),
		  __entry->size)
);

TRACE_EVENT(
	kvmi_send_event,
	TP_PROTO(__u32 id),
	TP_ARGS(id),
	TP_STRUCT__entry(
		__field(__u32, id)
	),
	TP_fast_assign(
		__entry->id = id;
	),
	TP_printk("%s",
		trace_print_symbols_seq(p, __entry->id, kvmi_event_id_symbol))
);

#define KVMI_ACCESS_PRINTK() ({                                         \
	const char *saved_ptr = trace_seq_buffer_ptr(p);		\
	static const char * const access_str[] = {			\
		"---", "r--", "-w-", "rw-", "--x", "r-x", "-wx", "rwx"  \
	};							        \
	trace_seq_printf(p, "%s", access_str[__entry->access & 7]);	\
	saved_ptr;							\
})

TRACE_EVENT(
	kvmi_set_mem_access,
	TP_PROTO(__u64 gfn, __u8 access, int err),
	TP_ARGS(gfn, access, err),
	TP_STRUCT__entry(
		__field(__u64, gfn)
		__field(__u8, access)
		__field(int, err)
	),
	TP_fast_assign(
		__entry->gfn = gfn;
		__entry->access = access;
		__entry->err = err;
	),
	TP_printk("gfn %llx %s %s %d",
		  __entry->gfn, KVMI_ACCESS_PRINTK(),
		  __entry->err ? "failed" : "succeeded", __entry->err)
);

TRACE_EVENT(
	kvmi_apply_mem_access,
	TP_PROTO(__u64 gfn, __u8 access, int err),
	TP_ARGS(gfn, access, err),
	TP_STRUCT__entry(
		__field(__u64, gfn)
		__field(__u8, access)
		__field(int, err)
	),
	TP_fast_assign(
		__entry->gfn = gfn;
		__entry->access = access;
		__entry->err = err;
	),
	TP_printk("gfn %llx %s flush %s %d",
		  __entry->gfn, KVMI_ACCESS_PRINTK(),
		  __entry->err ? "failed" : "succeeded", __entry->err)
);

TRACE_EVENT(
	kvmi_event_cr,
	TP_PROTO(__u16 vcpu, __u32 cr, __u64 old_value, __u64 new_value,
		 __u32 action),
	TP_ARGS(vcpu, cr, old_value, new_value, action),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u32, cr)
		__field(__u64, old_value)
		__field(__u64, new_value)
		__field(__u32, action)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->cr = cr;
		__entry->old_value = old_value;
		__entry->new_value = new_value;
		__entry->action = action;
	),
	TP_printk("vcpu %x cr %x old_value %llx new_value %llx -> %s",
		  __entry->vcpu,
		  __entry->cr,
		  __entry->old_value,
		  __entry->new_value,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol)
	)
);

TRACE_EVENT(
	kvmi_event_msr,
	TP_PROTO(__u16 vcpu, __u32 msr, __u64 old_value, __u64 new_value,
		 __u32 action),
	TP_ARGS(vcpu, msr, old_value, new_value, action),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u32, msr)
		__field(__u64, old_value)
		__field(__u64, new_value)
		__field(__u32, action)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->msr = msr;
		__entry->old_value = old_value;
		__entry->new_value = new_value;
		__entry->action = action;
	),
	TP_printk("vcpu %x msr %x old_value %llx new_value %llx -> %s",
		  __entry->vcpu,
		  __entry->msr,
		  __entry->old_value,
		  __entry->new_value,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol)
	)
);

TRACE_EVENT(
	kvmi_event_xsetbv,
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
	TP_printk("vcpu %x -> %s",
		  __entry->vcpu,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol)
	)
);

TRACE_EVENT(
	kvmi_event_breakpoint,
	TP_PROTO(__u16 vcpu, __u64 gpa, __u64 old_rip, __u32 action,
		 __u64 new_rip),
	TP_ARGS(vcpu, gpa, old_rip, action, new_rip),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u64, gpa)
		__field(__u64, old_rip)
		__field(__u32, action)
		__field(__u64, new_rip)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->gpa = gpa;
		__entry->old_rip = old_rip;
		__entry->action = action;
		__entry->new_rip = new_rip;
	),
	TP_printk("vcpu %x gpa %llx rip %llx -> %s rip %llx",
		  __entry->vcpu,
		  __entry->gpa,
		  __entry->old_rip,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol),
		  __entry->new_rip
	)
);

TRACE_EVENT(
	kvmi_event_hypercall,
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
	TP_printk("vcpu %x -> %s",
		  __entry->vcpu,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol)
	)
);

TRACE_EVENT(
	kvmi_event_page_fault,
	TP_PROTO(__u16 vcpu, __u64 gpa, __u64 gva, __u8 access, __u64 old_rip,
		 __u32 action, __u64 new_rip, __u32 ctx_size),
	TP_ARGS(vcpu, gpa, gva, access, old_rip, action, new_rip, ctx_size),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u64, gpa)
		__field(__u64, gva)
		__field(__u8, access)
		__field(__u64, old_rip)
		__field(__u32, action)
		__field(__u64, new_rip)
		__field(__u32, ctx_size)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->gpa = gpa;
		__entry->gva = gva;
		__entry->access = access;
		__entry->old_rip = old_rip;
		__entry->action = action;
		__entry->new_rip = new_rip;
		__entry->ctx_size = ctx_size;
	),
	TP_printk("vcpu %x gpa %llx %s gva %llx rip %llx -> %s rip %llx ctx %u",
		  __entry->vcpu,
		  __entry->gpa,
		  KVMI_ACCESS_PRINTK(),
		  __entry->gva,
		  __entry->old_rip,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol),
		  __entry->new_rip, __entry->ctx_size
	)
);

TRACE_EVENT(
	kvmi_event_trap,
	TP_PROTO(__u16 vcpu, __u32 vector, __u8 nr, __u32 err, __u16 error_code,
		 __u32 cr2, __u32 action),
	TP_ARGS(vcpu, vector, nr, err, error_code, cr2, action),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u32, vector)
		__field(__u8, nr)
		__field(__u32, err)
		__field(__u16, error_code)
		__field(__u32, cr2)
		__field(__u32, action)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu,
		__entry->vector = vector;
		__entry->nr = nr;
		__entry->err = err;
		__entry->error_code = error_code;
		__entry->cr2 = cr2;
		__entry->action = action;
	),
	TP_printk("vcpu %x vector %x/%x err %x/%x address %x -> %s",
		  __entry->vcpu,
		  __entry->vector, __entry->nr,
		  __entry->err, __entry->error_code,
		  __entry->cr2,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol)
	)
);

TRACE_EVENT(
	kvmi_event_descriptor,
	TP_PROTO(__u16 vcpu, __u32 exit_info, __u64 exit_qualification,
		 __u8 descriptor, __u8 write, __u32 action),
	TP_ARGS(vcpu, exit_info, exit_qualification, descriptor, write, action),
	TP_STRUCT__entry(
		__field(__u16, vcpu)
		__field(__u32, exit_info)
		__field(__u64, exit_qualification)
		__field(__u8, descriptor)
		__field(__u8, write)
		__field(__u32, action)
	),
	TP_fast_assign(
		__entry->vcpu = vcpu,
		__entry->exit_info = exit_info;
		__entry->exit_qualification = exit_qualification;
		__entry->descriptor = descriptor;
		__entry->write = write;
		__entry->action = action;
	),
	TP_printk("vcpu %x %s %s exit_info %x exit_qualification %llx -> %s",
		  __entry->vcpu,
		  __entry->write ? "write" : "read",
		  trace_print_symbols_seq(p, __entry->descriptor,
					  kvmi_descriptor_symbol),
		  __entry->exit_info,
		  __entry->exit_qualification,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol)
	)
);

TRACE_EVENT(
	kvmi_event_create_vcpu,
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
	TP_printk("vcpu %x -> %s",
		  __entry->vcpu,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol)
	)
);
TRACE_EVENT(
	kvmi_event_pause_vcpu,
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
	TP_printk("vcpu %x -> %s",
		  __entry->vcpu,
		  trace_print_symbols_seq(p, __entry->action,
					  kvmi_action_symbol)
	)
);
#endif /* _TRACE_KVMI_H */

#include <trace/define_trace.h>
