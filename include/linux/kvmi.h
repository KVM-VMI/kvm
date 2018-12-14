/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_H__
#define __KVMI_H__

#define kvmi_is_present() IS_ENABLED(CONFIG_KVM_INTROSPECTION)

#ifdef CONFIG_KVM_INTROSPECTION

int kvmi_init(void);
void kvmi_uninit(void);
void kvmi_create_vm(struct kvm *kvm);
void kvmi_destroy_vm(struct kvm *kvm);
int kvmi_hook(struct kvm *kvm, const struct kvm_introspection *qemu);
int kvmi_notify_unhook(struct kvm *kvm);
int kvmi_vcpu_init(struct kvm_vcpu *vcpu);
void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu);
bool kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
		   unsigned long old_value, unsigned long *new_value);
bool kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr);
void kvmi_xsetbv_event(struct kvm_vcpu *vcpu);
bool kvmi_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva);
bool kvmi_hypercall_event(struct kvm_vcpu *vcpu);
bool kvmi_lost_exception(struct kvm_vcpu *vcpu);
void kvmi_trap_event(struct kvm_vcpu *vcpu);
bool kvmi_descriptor_event(struct kvm_vcpu *vcpu, u32 info,
			   unsigned long exit_qualification,
			   unsigned char descriptor, unsigned char write);
bool kvmi_tracked_gfn(struct kvm_vcpu *vcpu, gfn_t gfn);
bool kvmi_track_emul_unimplemented(struct kvm_vcpu *vcpu, gpa_t gpa);
void kvmi_handle_requests(struct kvm_vcpu *vcpu);
int kvmi_host_mem_map(struct kvm_vcpu *vcpu, gva_t tkn_gva,
			     gpa_t req_gpa, gpa_t map_gpa);
int kvmi_host_mem_unmap(struct kvm_vcpu *vcpu, gpa_t map_gpa);
bool kvmi_monitored_msr(struct kvm_vcpu *vcpu, u32 msr);
void kvmi_stop_ss(struct kvm_vcpu *vcpu);
bool kvmi_vcpu_enabled_ss(struct kvm_vcpu *vcpu);
void kvmi_init_emulate(struct kvm_vcpu *vcpu);
void kvmi_activate_rep_complete(struct kvm_vcpu *vcpu);
bool kvmi_update_ad_flags(struct kvm_vcpu *vcpu);
bool kvmi_bp_intercepted(struct kvm_vcpu *vcpu, u32 dbg);

#else

static inline int kvmi_init(void) { return 0; }
static inline void kvmi_uninit(void) { }
static inline void kvmi_create_vm(struct kvm *kvm) { }
static inline void kvmi_destroy_vm(struct kvm *kvm) { }
static inline int kvmi_hook(struct kvm *kvm,
			const struct kvm_introspection *qemu)
			{ return 0; }
static inline int kvmi_notify_unhook(struct kvm *kvm) { return 0; }
static inline int kvmi_vcpu_init(struct kvm_vcpu *vcpu) { return 0; }
static inline void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu) { }
static inline bool kvmi_tracked_gfn(struct kvm_vcpu *vcpu, gfn_t gfn)
			{ return false; }
static inline bool kvmi_monitored_msr(struct kvm_vcpu *vcpu, u32 msr)
			{ return false; }
static inline bool kvmi_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva)
			{ return true; }
static inline bool kvmi_descriptor_event(struct kvm_vcpu *vcpu, u32 info,
			   unsigned long exit_qualification,
			   unsigned char descriptor, unsigned char write)
				{ return true; }
static inline bool kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
		   unsigned long old_value, unsigned long *new_value)
				{ return true; }
static inline void kvmi_xsetbv_event(struct kvm_vcpu *vcpu) { }
static inline bool kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr)
				{ return true; }
static inline bool kvmi_track_emul_unimplemented(struct kvm_vcpu *vcpu,
						gpa_t gpa)
				{ return true; }
static inline bool kvmi_hypercall_event(struct kvm_vcpu *vcpu) { return false; }
static inline void kvmi_handle_requests(struct kvm_vcpu *vcpu) { }
static inline bool kvmi_lost_exception(struct kvm_vcpu *vcpu) { return false; }
static inline void kvmi_trap_event(struct kvm_vcpu *vcpu) { }
static inline void kvmi_stop_ss(struct kvm_vcpu *vcpu) { }
static inline bool kvmi_vcpu_enabled_ss(struct kvm_vcpu *vcpu) { return false; }
static inline void kvmi_init_emulate(struct kvm_vcpu *vcpu) { }
static inline void kvmi_activate_rep_complete(struct kvm_vcpu *vcpu) { }
static inline bool kvmi_update_ad_flags(struct kvm_vcpu *vcpu) { return false; }
static inline bool kvmi_bp_intercepted(struct kvm_vcpu *vcpu, u32 dbg)
				{ return false; }
#endif /* CONFIG_KVM_INTROSPECTION */

#endif
