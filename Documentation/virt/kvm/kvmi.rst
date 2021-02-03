.. SPDX-License-Identifier: GPL-2.0

=========================================================
KVMI - The kernel virtual machine introspection subsystem
=========================================================

The KVM introspection subsystem provides a facility for applications running
on the host or in a separate VM, to control the execution of other VMs
(pause, resume, shutdown), query the state of the vCPUs (GPRs, MSRs etc.),
alter the page access bits in the shadow page tables (only for the hardware
backed ones, eg. Intel's EPT) and receive notifications when events of
interest have taken place (shadow page table level faults, key MSR writes,
hypercalls etc.). Some notifications can be responded to with an action
(like preventing an MSR from being written), others are mere informative
(like breakpoint events which can be used for execution tracing).
With few exceptions, all events are optional. An application using this
subsystem will explicitly register for them.

The use case that gave way for the creation of this subsystem is to monitor
the guest OS and as such the ABI/API is highly influenced by how the guest
software (kernel, applications) sees the world. For example, some events
provide information specific for the host CPU architecture
(eg. MSR_IA32_SYSENTER_EIP) merely because its leveraged by guest software
to implement a critical feature (fast system calls).

At the moment, the target audience for KVMI are security software authors
that wish to perform forensics on newly discovered threats (exploits) or
to implement another layer of security like preventing a large set of
kernel rootkits simply by "locking" the kernel image in the shadow page
tables (ie. enforce .text r-x, .rodata rw- etc.). It's the latter case that
made KVMI a separate subsystem, even though many of these features are
available in the device manager (eg. QEMU). The ability to build a security
application that does not interfere (in terms of performance) with the
guest software asks for a specialized interface that is designed for minimum
overhead.

API/ABI
=======

This chapter describes the VMI interface used to monitor and control local
guests from a user application.

Overview
--------

The interface is socket based, one connection for every VM. One end is in the
host kernel while the other is held by the user application (introspection
tool).

The initial connection is established by an application running on the host
(eg. QEMU) that connects to the introspection tool and after a handshake the
socket is passed to the host kernel making all further communication take
place between it and the introspection tool. The initiating party (QEMU) can
close its end so that any potential exploits cannot take a hold of it.

The socket protocol allows for commands and events to be multiplexed over
the same connection. As such, it is possible for the introspection tool to
receive an event while waiting for the result of a command. Also, it can
send a command while the host kernel is waiting for a reply to an event.

The kernel side of the socket communication is blocking and will wait for
an answer from its peer indefinitely or until the guest is powered off
(killed), restarted or the peer goes away, at which point it will wake
up and properly cleanup as if the introspection subsystem has never been
used on that guest. Obviously, whether the guest can really continue
normal execution depends on whether the introspection tool has made any
modifications that require an active KVMI channel.

All messages (commands or events) have a common header::

	struct kvmi_msg_hdr {
		__u16 id;
		__u16 size;
		__u32 seq;
	};

The replies have the same header, with the sequence number (``seq``)
and message id (``id``) matching the command/event.

After ``kvmi_msg_hdr``, ``id`` specific data of ``size`` bytes will
follow.

The message header and its data must be sent with one ``sendmsg()`` call
to the socket. This simplifies the receiver loop and avoids
the reconstruction of messages on the other side.

The wire protocol uses the host native byte-order. The introspection tool
must check this during the handshake and do the necessary conversion.

A command reply begins with::

	struct kvmi_error_code {
		__s32 err;
		__u32 padding;
	}

followed by the command specific data if the error code ``err`` is zero.

The error code -KVM_ENOSYS is returned for unsupported commands.

The error code -KVM_EPERM is returned for disallowed commands (see **Hooking**).

The error code is related to the message processing, including unsupported
commands. For all the other errors (incomplete messages, wrong sequence
numbers, socket errors etc.) the socket will be closed. The device
manager should reconnect.

While all commands will have a reply as soon as possible, the replies
to events will probably be delayed until a set of (new) commands will
complete::

   Host kernel               Tool
   -----------               ----
   event 1 ->
                             <- command 1
   command 1 reply ->
                             <- command 2
   command 2 reply ->
                             <- event 1 reply

If both ends send a message at the same time::

   Host kernel               Tool
   -----------               ----
   event X ->                <- command X

the host kernel will reply to 'command X', regardless of the receive time
(before or after the 'event X' was sent).

As it can be seen below, the wire protocol specifies occasional padding. This
is to permit working with the data by directly using C structures or to round
the structure size to a multiple of 8 bytes (64bit) to improve the copy
operations that happen during ``recvmsg()`` or ``sendmsg()``. The members
should have the native alignment of the host (4 bytes on x86). All padding
must be initialized with zero otherwise the respective commands will fail
with -KVM_EINVAL.

To describe the commands/events, we reuse some conventions from api.txt:

  - Architectures: which instruction set architectures provide this command/event

  - Versions: which versions provide this command/event

  - Parameters: incoming message data

  - Returns: outgoing/reply message data

Handshake
---------

Although this falls out of the scope of the introspection subsystem, below
is a proposal of a handshake that can be used by implementors.

Based on the system administration policies, the management tool
(eg. libvirt) starts device managers (eg. QEMU) with some extra arguments:
what introspection tool could monitor/control that specific guest (and
how to connect to) and what introspection commands/events are allowed.

The device manager will connect to the introspection tool and wait for a
cryptographic hash of a cookie that should be known by both peers. If the
hash is correct (the destination has been "authenticated"), the device
manager will send another cryptographic hash and random salt. The peer
recomputes the hash of the cookie bytes including the salt and if they match,
the device manager has been "authenticated" too. This is a rather crude
system that makes it difficult for device manager exploits to trick the
introspection tool into believing its working OK.

The cookie would normally be generated by a management tool (eg. libvirt)
and make it available to the device manager and to a properly authenticated
client. It is the job of a third party to retrieve the cookie from the
management application and pass it over a secure channel to the introspection
tool.

Once the basic "authentication" has taken place, the introspection tool
can receive information on the guest (its UUID) and other flags (endianness
or features supported by the host kernel).

In the end, the device manager will pass the file handle (plus the allowed
commands/events) to KVM, and forget about it. It will be notified by
KVM when the introspection tool closes the file handle (in case of
errors), and should reinitiate the handshake.

Once the file handle reaches KVM, the introspection tool should
use the *KVMI_GET_VERSION* command to get the API version and/or the
*KVMI_VM_CHECK_COMMAND* and *KVMI_VM_CHECK_EVENT* commands to see which
commands/events are allowed for this guest. The error code -KVM_EPERM
will be returned if the introspection tool uses a command or enables an
event which is disallowed.

Unhooking
---------

During a VMI session it is possible for the guest to be patched and for
some of these patches to "talk" with the introspection tool. It thus
becomes necessary to remove them before the guest is suspended, moved
(migrated) or a snapshot with memory is created.

The actions are normally performed by the device manager. In the case
of QEMU, it will use the *KVM_INTROSPECTION_PREUNHOOK* ioctl to trigger
the *KVMI_EVENT_UNHOOK* event and wait for a limited amount of time
(a few seconds) for a confirmation from the introspection tool that is
OK to proceed.

Live migrations
---------------

Before the live migration takes place, the introspection tool has to be
notified and have a chance to unhook (see **Unhooking**).

The QEMU instance on the receiving end, if configured for KVMI, will need
to establish a connection to the introspection tool after the migration
has completed.

Obviously, this creates a window in which the guest is not introspected.
The user will need to be aware of this detail. Future introspection
technologies can choose not to disconnect and instead transfer the
necessary context to the introspection tool at the migration destination
via a separate channel.

Memory access safety
--------------------

The KVMI API gives access to the entire guest physical address space but
provides no information on which parts of it are system RAM and which are
device-specific memory (DMA, emulated MMIO, reserved by a passthrough
device etc.). It is up to the user to determine, using the guest operating
system data structures, the areas that are safe to access (code, stack, heap
etc.).

Commands
--------

The following C structures are meant to be used directly when communicating
over the wire. The peer that detects any size mismatch should simply close
the connection and report the error.

The commands related to vCPUs start with::

	struct kvmi_vcpu_hdr {
		__u16 vcpu;
		__u16 padding1;
		__u32 padding2;
	}

1. KVMI_GET_VERSION
-------------------

:Architectures: all
:Versions: >= 1
:Parameters: none
:Returns:

::

	struct kvmi_error_code;
	struct kvmi_get_version_reply {
		__u32 version;
		__u32 padding;
		struct kvmi_features features;
	};

For x86

::

	struct kvmi_features {
		__u8 singlestep;
		__u8 vmfunc;
		__u8 eptp;
		__u8 ve;
		__u8 spp;
		__u8 padding[3];
	};

Returns the introspection API version and some of the features supported
by the hardware (eg. alternate EPT views, virtualization exception,
sub-page protection).

This command is always allowed and successful (if the introspection is
built in kernel).

2. KVMI_VM_CHECK_COMMAND
------------------------

:Architectures: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vm_check_command {
		__u16 id;
		__u16 padding1;
		__u32 padding2;
	};

:Returns:

::

	struct kvmi_error_code;

Checks if the command specified by ``id`` is allowed.

This command is always allowed.

:Errors:

* -KVM_EPERM - the command specified by ``id`` is disallowed
* -KVM_EINVAL - padding is not zero
* -KVM_EINVAL - the command specified by ``id`` is not known

3. KVMI_VM_CHECK_EVENT
----------------------

:Architectures: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vm_check_event {
		__u16 id;
		__u16 padding1;
		__u32 padding2;
	};

:Returns:

::

	struct kvmi_error_code;

Checks if the event specified by ``id`` is allowed.

This command is always allowed.

:Errors:

* -KVM_EPERM - the event specified by ``id`` is disallowed
* -KVM_EINVAL - padding is not zero
* -KVM_EINVAL - the event specified by ``id`` is not known

4. KVMI_VM_GET_INFO
-------------------

:Architectures: all
:Versions: >= 1
:Parameters: none
:Returns:

::

	struct kvmi_error_code;
	struct kvmi_vm_get_info_reply {
		__u32 vcpu_count;
		__u32 padding[3];
	};

Returns the number of online vCPUs.

5. KVMI_VM_CONTROL_EVENTS
-------------------------

:Architectures: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vm_control_events {
		__u16 event_id;
		__u8 enable;
		__u8 padding1;
		__u32 padding2;
	};

:Returns:

::

	struct kvmi_error_code

Enables/disables VM introspection events. This command can be used with
the following events::

	KVMI_EVENT_CREATE_VCPU
	KVMI_EVENT_UNHOOK

:Errors:

* -KVM_EINVAL - the event ID is invalid/unknown (use *KVMI_VM_CHECK_EVENT* first)
* -KVM_EINVAL - padding is not zero
* -KVM_EPERM - the access is restricted by the host

6. KVMI_VM_READ_PHYSICAL
------------------------

:Architectures: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vm_read_physical {
		__u64 gpa;
		__u64 size;
	};

:Returns:

::

	struct kvmi_error_code;
	__u8 data[0];

Reads from the guest memory.

Currently, the size must be non-zero and the read must be restricted to
one page (offset + size <= PAGE_SIZE).

:Errors:

* -KVM_EINVAL - the specified gpa/size pair is invalid
* -KVM_ENOENT - the guest page doesn't exists

7. KVMI_VM_WRITE_PHYSICAL
-------------------------

:Architectures: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vm_write_physical {
		__u64 gpa;
		__u64 size;
		__u8  data[0];
	};

:Returns:

::

	struct kvmi_error_code

Writes into the guest memory.

Currently, the size must be non-zero and the write must be restricted to
one page (offset + size <= PAGE_SIZE).

:Errors:

* -KVM_EINVAL - the specified gpa/size pair is invalid
* -KVM_ENOENT - the guest page doesn't exists

8. KVMI_VCPU_GET_INFO
---------------------

:Architectures: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;

:Returns:

::

	struct kvmi_error_code;
	struct kvmi_vcpu_get_info_reply {
		__u64 tsc_speed;
	};

Returns the TSC frequency (in HZ) for the specified vCPU if available
(otherwise it returns zero).

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet

9. KVMI_VCPU_PAUSE
------------------

:Architecture: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_pause {
		__u8 wait;
		__u8 padding1;
		__u16 padding2;
		__u32 padding3;
	};

:Returns:

::

	struct kvmi_error_code;

Kicks the vCPU from guest.

If `wait` is 1, the command will wait for vCPU to acknowledge the IPI.

The vCPU will handle the pending commands/events and send the
*KVMI_EVENT_PAUSE_VCPU* event (one for every successful *KVMI_VCPU_PAUSE*
command) before returning to guest.

Please note that new vCPUs might by created at any time.
The introspection tool should use *KVMI_VM_CONTROL_EVENTS* to enable the
*KVMI_EVENT_CREATE_VCPU* event in order to stop these new vCPUs as well
(by delaying the event reply).

The socket will be closed if the *KVMI_EVENT_PAUSE_VCPU* event is disallowed.
Use *KVMI_VM_CHECK_EVENT* first.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_EBUSY  - the selected vCPU has too many queued *KVMI_EVENT_PAUSE_VCPU* events

10. KVMI_VCPU_CONTROL_EVENTS
----------------------------

:Architectures: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_control_events {
		__u16 event_id;
		__u8 enable;
		__u8 padding1;
		__u32 padding2;
	};

:Returns:

::

	struct kvmi_error_code

Enables/disables vCPU introspection events. This command can be used with
the following events::

	KVMI_EVENT_BREAKPOINT
	KVMI_EVENT_CR
	KVMI_EVENT_DESCRIPTOR
	KVMI_EVENT_HYPERCALL
	KVMI_EVENT_MSR
	KVMI_EVENT_PF
	KVMI_EVENT_SINGLESTEP
	KVMI_EVENT_XSETBV
	KVMI_EVENT_CPUID

When an event is enabled, the introspection tool is notified and it
must reply with: continue, retry, crash, etc. (see **Events** below).

The *KVMI_EVENT_PAUSE_VCPU* event is always enabled,
because it is triggered by the *KVMI_VCPU_PAUSE* command.

The *KVMI_EVENT_TRAP* event is always enabled,
because it is triggered by the *KVMI_VCPU_INJECT_EXCEPTION* command.

The *KVMI_EVENT_CREATE_VCPU* and *KVMI_EVENT_UNHOOK* events are controlled
by the *KVMI_VM_CONTROL_EVENTS* command.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - the event ID is invalid/unknown (use *KVMI_VM_CHECK_EVENT* first)
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_EPERM - the access is restricted by the host
* -KVM_EOPNOTSUPP - the event can't be intercepted in the current setup
                    (e.g. KVMI_EVENT_DESCRIPTOR with AMD)
* -KVM_EBUSY - the event can't be intercepted right now
               (e.g. KVMI_EVENT_BREAKPOINT if the #BP event is already intercepted
                by userspace)

11. KVMI_VCPU_GET_REGISTERS
---------------------------

:Architectures: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_get_registers {
		__u16 nmsrs;
		__u16 padding1;
		__u32 padding2;
		__u32 msrs_idx[0];
	};

:Returns:

::

	struct kvmi_error_code;
	struct kvmi_vcpu_get_registers_reply {
		__u32 mode;
		__u32 padding;
		struct kvm_regs regs;
		struct kvm_sregs sregs;
		struct kvm_msrs msrs;
	};

For the given vCPU and the ``nmsrs`` sized array of MSRs registers,
returns the current vCPU mode (in bytes: 2, 4 or 8), the general purpose
registers, the special registers and the requested set of MSRs.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - one of the indicated MSRs is invalid
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_ENOMEM - not enough memory to allocate the reply

12. KVMI_VCPU_SET_REGISTERS
---------------------------

:Architectures: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvm_regs;

:Returns:

::

	struct kvmi_error_code

Sets the general purpose registers for the given vCPU. The changes become
visible to other threads accessing the KVM vCPU structure after the event
currently being handled is replied to.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_EOPNOTSUPP - the command hasn't been received during an introspection event

13. KVMI_VCPU_GET_CPUID
-----------------------

:Architectures: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_get_cpuid {
		__u32 function;
		__u32 index;
	};

:Returns:

::

	struct kvmi_error_code;
	struct kvmi_vcpu_get_cpuid_reply {
		__u32 eax;
		__u32 ebx;
		__u32 ecx;
		__u32 edx;
	};

Returns a CPUID leaf (as seen by the guest OS).

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_ENOENT - the selected leaf is not present or is invalid

14. KVMI_VCPU_CONTROL_CR
------------------------

:Architectures: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_control_cr {
		__u8 enable;
		__u8 padding1;
		__u16 padding2;
		__u32 cr;
	};

:Returns:

::

	struct kvmi_error_code

Enables/disables introspection for a specific control register and must
be used in addition to *KVMI_VCPU_CONTROL_EVENTS* with the *KVMI_EVENT_CR*
ID set.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - the specified control register is not part of the CR0, CR3
   or CR4 set
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet

15. KVMI_VCPU_INJECT_EXCEPTION
------------------------------

:Architectures: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_inject_exception {
		__u8 nr;
		__u8 padding1;
		__u16 padding2;
		__u32 error_code;
		__u64 address;
	};

:Returns:

::

	struct kvmi_error_code

Injects a vCPU exception with or without an error code. In case of page fault
exception, the guest virtual address has to be specified.

An *KVMI_EVENT_TRAP* event will be send as soon as possible.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - the specified exception number is invalid
* -KVM_EINVAL - the specified address is invalid
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_EBUSY - another *KVMI_VCPU_INJECT_EXCEPTION* command was issued and no
  corresponding *KVMI_EVENT_TRAP* (if enabled) has been provided yet.

16. KVMI_VM_GET_MAX_GFN
-----------------------

:Architecture: all
:Versions: >= 1
:Parameters: none
:Returns:

::

        struct kvmi_error_code;
        struct kvmi_vm_get_max_gfn_reply {
                __u64 gfn;
        };

Provides the maximum GFN allocated to the VM by walking through all
memory slots allocated by KVM, considering all address spaces indicated
by KVM_ADDRESS_SPACE_NUM. Stricly speaking, the returned value refers
to the first inaccessible GFN, next to the maximum accessible GFN.

17. KVMI_VCPU_GET_XSAVE
-----------------------

:Architecture: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;

:Returns:

::

	struct kvmi_error_code;
	struct kvmi_vcpu_get_xsave_reply {
		__u32 region[0];
	};

Returns a buffer containing the XSAVE area. Currently, the size of
``kvm_xsave`` is used, but it could change. The userspace should get
the buffer size from the message size.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_ENOMEM - not enough memory to allocate the reply

18. KVMI_VCPU_GET_MTRR_TYPE
---------------------------

:Architecture: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_get_mtrr_type {
		__u64 gpa;
	};

:Returns:

::

	struct kvmi_error_code;
	struct kvmi_vcpu_get_mtrr_type_reply {
		__u8 type;
		__u8 padding[7];
	};

Returns the guest memory type for a specific physical address.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet

19. KVMI_VCPU_CONTROL_MSR
-------------------------

:Architectures: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_control_msr {
		__u8 enable;
		__u8 padding1;
		__u16 padding2;
		__u32 msr;
	};

:Returns:

::

	struct kvmi_error_code

Enables/disables introspection for a specific MSR and must be used
in addition to *KVMI_VCPU_CONTROL_EVENTS* with the *KVMI_EVENT_MSR* ID set.

Currently, only MSRs within the following two ranges are supported. Trying
to control events for any other register will fail with -KVM_EINVAL::

	0          ... 0x00001fff
	0xc0000000 ... 0xc0001fff

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - the specified MSR is invalid
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet

20. KVMI_VM_SET_PAGE_ACCESS
---------------------------

:Architectures: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vm_set_page_access {
		__u16 count;
		__u16 view;
		__u32 padding;
		struct kvmi_page_access_entry entries[0];
	};

where::

	struct kvmi_page_access_entry {
		__u64 gpa;
		__u8 access;
		__u8 padding1;
		__u16 padding2;
		__u32 padding3;
	};


:Returns:

::

	struct kvmi_error_code

Sets the spte access bits (rwx) for an array of ``count`` guest physical
addresses, for the selected EPT view.

The valid access bits are::

	KVMI_PAGE_ACCESS_R
	KVMI_PAGE_ACCESS_W
	KVMI_PAGE_ACCESS_X


The command will fail with -KVM_EINVAL if any of the specified combination
of access bits is not supported.

The command will try to apply all changes and return the first error if
some failed. The introspection tool should handle the rollback.

In order to 'forget' an address, all the access bits ('rwx') must be set.

:Errors:

* -KVM_EINVAL - the specified access bits combination is invalid
* -KVM_EINVAL - the padding is not zero
* -KVM_EINVAL - the selected EPT view is invalid (see *KVM_MAX_EPT_VIEWS*)
* -KVM_EINVAL - the message size is invalid
* -KVM_EOPNOTSUPP - a non-zero EPT view was selected but SPP is enabled for this VM
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_ENOMEM - not enough memory to add the page tracking structures

20. KVMI_VCPU_CONTROL_SINGLESTEP
--------------------------------

:Architectures: x86 (vmx)
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_control_singlestep {
		__u8 enable;
		__u8 padding[7];
	};

:Returns:

::

	struct kvmi_error_code

Enables/disables singlestep.

The introspection tool can use *KVMI_GET_VERSION*, to check
if the hardware supports singlestep (see **KVMI_GET_VERSION**).

:Errors:

* -KVM_EOPNOTSUPP - the hardware doesn't support it
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet

21. KVMI_VCPU_TRANSLATE_GVA
---------------------------

:Architecture: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_translate_gva {
		__u64 gva;
	};

:Returns:

::

	struct kvmi_error_code;
	struct kvmi_vcpu_translate_gva_reply {
		__u64 gpa;
	};

Translates a guest virtual address to a guest physical address or ~0 if
the address cannot be translated.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EAGAIN - the selected vCPU can't be introspected yet

22. KVMI_VCPU_GET_EPT_VIEW
--------------------------

:Architecture: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;

:Returns:

::

	struct kvmi_error_code;
	struct kvmi_vcpu_get_ept_view_reply {
		__u16 view;
		__u16 padding1;
		__u32 padding2;
	};

Returns the EPT ``view`` the provided vCPU operates on.

Before getting EPT views, the introspection tool should use
*KVMI_GET_VERSION* to check if the hardware has support for VMFUNC and
EPTP switching mechanism (see **KVMI_GET_VERSION**).  If the hardware
does not provide support for these features, the returned EPT view will
be zero.

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EAGAIN - the selected vCPU can't be introspected yet

23. KVMI_VCPU_SET_EPT_VIEW
--------------------------

:Architecture: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_set_ept_view {
		__u16 view;
		__u16 padding1;
		__u32 padding2;
	};

:Returns:

::

	struct kvmi_error_code;

Configures the vCPU to use the provided ``view``.

Before switching EPT views, the introspection tool should use
*KVMI_GET_VERSION* to check if the hardware has support for VMFUNC and
EPTP switching mechanism (see **KVMI_GET_VERSION**).

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_EINVAL - padding is not zero
* -KVM_EOPNOTSUPP - a non-zero EPT view was selected but SPP is enabled for this VM
* -KVM_EINVAL - the selected EPT view is invalid (see *KVM_MAX_EPT_VIEWS*)

24. KVMI_VCPU_CONTROL_EPT_VIEW
------------------------------

:Architecture: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_control_ept_view {
		__u16 view;
		__u8  visible;
		__u8  padding1;
		__u32 padding2;
	};

:Returns:

::

	struct kvmi_error_code;

Controls the capability of the guest to successfully change EPT views
through VMFUNC instruction without triggering a vm-exit. If ``visible``
is true, the guest will be capable to change EPT views through VMFUNC(0,
``view``). If ``visible`` is false, VMFUNC(0, ``view``) triggers a
vm-exit, a #UD exception is injected to guest and the guest application
is terminated.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_EINVAL - padding is not zero
* -KVM_EINVAL - the selected EPT view is not valid
* -KVM_EOPNOTSUPP - SPP is enabled for this VM
* -KVM_EOPNOTSUPP - a non-zero EPT view was made visible but SPP is enabled for this VM
* -KVM_EINVAL - the selected EPT view is not valid (see *KVM_MAX_EPT_VIEWS*)

25. KVMI_VCPU_SET_VE_INFO
-------------------------

:Architecture: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_set_ve_info {
		__u64 gpa;
		__u8 trigger_vmexit;
		__u8 padding1;
		__u16 padding2;
		__u32 padding3;
	};

:Returns:

::

	struct kvmi_error_code;

Configures the guest physical address for the #VE info page and enables
the #VE mechanism. If ``trigger_vmexit`` is true, any virtualization
exception will trigger a vm-exit. Otherwise, the exception is delivered
using gate descriptor 20 from the Interrupt Descriptor Table (IDT).

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - one of the specified GPAs is invalid
* -KVM_EOPNOTSUPP - the hardware does not support #VE
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet

26. KVMI_VCPU_DISABLE_VE
------------------------

:Architecture: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;

:Returns:

::

	struct kvmi_error_code;

Disables the #VE mechanism. All EPT violations will trigger a vm-exit,
regardless of the corresponding spte 63rd bit (SVE) for the GPA that
triggered the EPT violation within a specific EPT view.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EAGAIN - the selected vCPU can't be introspected yet

27. KVMI_VM_SET_PAGE_SVE
------------------------

:Architecture: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vm_set_page_sve {
		__u16 view;
		__u8 suppress;
		__u8 padding1;
		__u32 padding2;
		__u64 gpa;
	};

:Returns:

::

        struct kvmi_error_code;

Configures the spte 63rd bit (Suppress #VE, SVE) for ``gpa`` on the
provided EPT ``view``. If ``suppress`` field is 1, the SVE bit will be set.
If it is 0, the SVE it will be cleared.

If the SVE bit is cleared, EPT violations generated by the provided
guest physical address will trigger a #VE instead of a #PF, which is
delivered using gate descriptor 20 in the IDT.

Before configuring the SVE bit, the introspection tool should use
*KVMI_GET_VERSION* to check if the hardware has support for the #VE
mechanism (see **KVMI_GET_VERSION**).

:Errors:

* -KVM_EINVAL - padding is not zero
* -KVM_ENOMEM - not enough memory to add the page tracking structures
* -KVM_EOPNOTSUPP - a non-zero EPT view was selected but SPP is enabled for this VM
* -KVM_EINVAL - the selected EPT view is not valid

25. KVMI_VM_GET_MAP_TOKEN
-------------------------

:Architecture: all
:Versions: >= 1
:Parameters: none
:Returns:

::

	struct kvmi_error_code;
	struct kvmi_vm_get_map_token_reply {
		struct kvmi_map_mem_token token;
	};

Where::

	struct kvmi_map_mem_token {
		__u64 token[4];
	};

Requests a token for a memory map operation.

On this command, the host generates a random token to be used (once)
to map a physical page from the introspected guest. The introspector
could use the token with the KVM_INTRO_MEM_MAP ioctl (on /dev/kvmmem)
to map a guest physical page to one of its memory pages. The ioctl,
in turn, will use the KVM_HC_MEM_MAP hypercall (see hypercalls.txt).

The guest kernel exposing /dev/kvmmem keeps a list with all the mappings
(to all the guests introspected by the tool) in order to unmap them
(using the KVM_HC_MEM_UNMAP hypercall) when /dev/kvmmem is closed or on
demand (using the KVM_INTRO_MEM_UNMAP ioctl).

:Errors:

* -KVM_EAGAIN - too many tokens have accumulated
* -KVM_ENOMEM - not enough memory to allocate a new token

26. KVMI_VM_CONTROL_CMD_RESPONSE
--------------------------------

:Architectures: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vm_control_cmd_response {
		__u8 enable;
		__u8 now;
		__u8 flags;
		__u8 padding1;
		__u32 padding2;
	};

:Returns:

::

	struct kvmi_error_code

Enables or disables the command replies.

By default, a reply is sent for any introspection commands (`enable=1`).

If `now` is 1, the command reply is enabled/disabled (according to
`enable`) starting with the current command. For example, `enable=0` and
`now=1` means that the reply is disabled for this command too, while
`enable=0` and `now=0` means that the reply is disabled starting with
the next command.

This command is used by the introspection tool to disable the replies
for commands returning an error code only (eg. *KVMI_VCPU_SET_REGISTERS*)
when an error is less likely to happen. For example, the following
commands can be used to reply to an event with a single `write()` call
and without waiting for a reply:

	KVMI_VM_CONTROL_CMD_RESPONSE enable=0 now=1
	KVMI_VCPU_SET_REGISTERS vcpu=N
	KVMI_EVENT_REPLY        vcpu=N
	KVMI_VM_CONTROL_CMD_RESPONSE enable=1 now=0

The following commands can be used to pause all vCPUs:

	KVMI_VM_CONTROL_CMD_RESPONSE enable=0 now=1
	KVMI_VCPU_PAUSE vcpu=0
	KVMI_VCPU_PAUSE_VCPU vcpu=1
	...
	KVMI_VM_CONTROL_CMD_RESPONSE enable=1 now=1

Waiting a reply for the last *KVMI_VM_CONTROL_CMD_RESPONSE* guarantees
that all vCPUs are kicked out of guest once the reply is received.

If `flags` has the LSB set to `1` and the command reply is disabled
(`enable=0`), an *KVMI_EVENT_CMD_ERROR* event will be sent when a
command fails.

When the command reply is disabled, the socket will be closed:

* on any command for which the reply should contain more than just an
  error code (eg. *KVMI_VCPU_GET_REGISTERS*)

* on any unsupported/unknown or disallowed commands

* if the *KVMI_EVENT_CMD_ERROR* event is disallowed by userspace and
  the introspection tool disables the command replies with the LSB from
  `flag` set to 1

27. KVMI_VM_CONTROL_SPP
-----------------------

:Architectures: x86/intel
:Versions: >= 1
:Parameters:

::

	struct kvmi_vm_control_spp {
		__u8 enable;
		__u8 padding1;
		__u16 padding2;
		__u32 padding3;
	};

:Returns:

::

	struct kvmi_error_code;

Enables/disables subpage protection (SPP) for the current VM.

If SPP is not enabled, the *KVMI_VM_SET_PAGE_WRITE_BITMAP* command
will fail.

:Errors:

* -KVM_EINVAL - padding is not zero
* -KVM_EOPNOTSUPP - the hardware doesn't support SPP
* -KVM_EOPNOTSUPP - the current implementation can't disable SPP
* -KVM_EOPNOTSUPP - at least one vCPU is running on a non-zero EPT-view

28. KVMI_VM_SET_PAGE_WRITE_BITMAP
---------------------------------

:Architectures: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vm_set_page_write_bitmap {
		__u16 padding1;
		__u16 count;
		__u32 padding2;
		struct kvmi_page_write_bitmap_entry entries[0];
	};

where::

	struct kvmi_page_write_bitmap_entry {
		__u64 gpa;
		__u32 bitmap;
		__u32 padding;
	};

:Returns:

::

	struct kvmi_error_code;

Sets the subpage protection (SPP) write bitmap for an array of ``count``
guest physical addresses of 4KB bytes.

The command will try to apply all changes and return the first error if
some failed. The introspection tool should handle the rollback.

While the *KVMI_VM_SET_PAGE_ACCESS* command can be used to write-protect a
4KB page, this command can write-protect 128-bytes subpages inside of a
4KB page by setting the corresponding bit to 1 (write allowed) or to 0
(write disallowed). For example, to allow write access to the A and B
subpages only, the bitmap must be set to::

	BIT(A) | BIT(B)

A and B must be a number between 0 (first subpage) and 31 (last subpage).

Using this command to set all bits to 1 (allow write access for
all subpages) will allow write access to the whole 4KB page (like a
*KVMI_VM_SET_PAGE_ACCESS* command with the *KVMI_PAGE_ACCESS_W* flag set)
and vice versa.

Using this command to set any bit to 0 will write-protect the whole 4KB
page (like a *KVMI_VM_SET_PAGE_ACCESS* command with the *KVMI_PAGE_ACCESS_W*
flag cleared) and allow write access only for subpages with the
corresponding bit set to 1.

:Errors:

* -KVM_EINVAL - the selected SPT view is invalid
* -KVM_EOPNOTSUPP - a SPT view was selected but the hardware doesn't support it
* -KVM_EOPNOTSUPP - the hardware doesn't support SPP or hasn't been enabled
* -KVM_EINVAL - the write access is already allowed for the whole 4KB page
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_ENOMEM - not enough memory to add the page tracking structures

29. KVMI_VCPU_GET_XCR
---------------------

:Architectures: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_get_xcr {
		__u8 xcr;
		__u8 padding[7];
	};

:Returns:

::

	struct kvmi_error_code;
	struct kvmi_vcpu_get_xcr_reply {
		__u64 value;
	};

Returns the value of the extended special register ``xcr`` for the
specified vCPU. Currently, only XCR0 is supported.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - the selected register is not supported.
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet

30. KVMI_VCPU_SET_XSAVE
-----------------------

:Architectures: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_set_xsave {
		__u32 region[0];
	};

:Returns:

::

	struct kvmi_error_code;

Modifies the XSAVE area.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EAGAIN - the selected vCPU can't be introspected yet

31. KVMI_VCPU_CHANGE_GFN
------------------------

:Architectures: x86
:Versions: >= 1
:Parameters:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_change_gfn {
		__u64 old_gfn;
		__u64 new_gfn;
	};

:Returns:

::

	struct kvmi_error_code;

Changes the content of ``old_gfn`` with the one provided through ``new_gfn``,
inside the current EPT view. Usage:

* change{gfn_1, gfn_2} - alters page table entries for gfn_1 so they point to
        the pfn that gfn_2 is mapped to; page table entries mapping gfn_2 must
        already be present

* change{gfn_1, gfn_1} - restores page table entries so they point to the pfn
        that gfn_1 was initially mapped to; page table entries mapping gfn_1
        must already be present

* change{gfn_1, ~0ULL} - reserved for future use

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_EPERM - reserved operation, ``new_gfn`` must not be (~0ULL)
* -KVM_EINVAL - provided gfn is not visible by KVM, meaning one of the following:
                a. the memory slot holding the gfn is marked as invalid
                b. the memory slot holding the gfn is not exposed to userspace
                c. the gfn does not belong to any memory slot
* -KVM_EINVAL - ``new_gfn`` (first case) or ``old_gfn`` (second case) has no
                mapping inside the current EPT view, no r/w access has been made
* -KVM_EINVAL - internal KVM error: provided gfn can't be translated
                to a valid pfn
* -KVM_ENOMEM - not enough memory to allocate new page tables for
                the current EPT view
* -KVM_EAGAIN - internal KVM error inside the MMU notifier subsystem
* -KVM_EFAULT - internal KVM error: one of the created page table
                entries points to a MMIO region
* -KVM_EAGAIN - internal KVM error: current root page table is invalid

Events
======

All introspection events (VM or vCPU related) are sent
using the *KVMI_EVENT* message id. No event will be sent unless
it is explicitly enabled (see *KVMI_VM_CONTROL_EVENTS* and *KVMI_VCPU_CONTROL_EVENTS*)
or requested (eg. *KVMI_EVENT_PAUSE_VCPU*).

There are two VM events (*KVMI_EVENT_UNHOOK*, *KVMI_EVENT_CMD_ERROR*),
which doesn't have a reply, but share the kvmi_event structure, for
consistency with the vCPU events.

The message data begins with a common structure, having the size of the
structure, the vCPU index and the event id::

	struct kvmi_event {
		__u16 size;
		__u16 vcpu;
		__u8 event;
		__u8 padding[3];
		struct kvmi_event_arch arch;
	}

On x86 the structure looks like this::

	struct kvmi_event_arch {
		__u8 mode;
		__u8 padding[7];
		struct kvm_regs regs;
		struct kvm_sregs sregs;
		struct {
			__u64 sysenter_cs;
			__u64 sysenter_esp;
			__u64 sysenter_eip;
			__u64 efer;
			__u64 star;
			__u64 lstar;
			__u64 cstar;
			__u64 pat;
			__u64 shadow_gs;
		} msrs;
	};

It contains information about the vCPU state at the time of the event.

The reply to events uses the *KVMI_EVENT_REPLY* message id and begins
with two common structures::

	struct kvmi_vcpu_hdr;
	struct kvmi_event_reply {
		__u8 action;
		__u8 event;
		__u16 padding1;
		__u32 padding2;
	};

All events accept the KVMI_EVENT_ACTION_CRASH action, which stops the
guest ungracefully, but as soon as possible.

Most of the events accept the KVMI_EVENT_ACTION_CONTINUE action, which
lets the instruction that caused the event to continue (unless specified
otherwise).

Some of the events accept the KVMI_EVENT_ACTION_RETRY action, to continue
by re-entering the guest.

Specific data can follow these common structures.

1. KVMI_EVENT_UNHOOK
--------------------

:Architecture: all
:Versions: >= 1
:Actions: none
:Parameters:

::

	struct kvmi_event;

:Returns: none

This event is sent when the device manager has to pause/stop/migrate
the guest (see **Unhooking**) and the introspection has been enabled
for this event (see **KVMI_VM_CONTROL_EVENTS**). The introspection tool
has a chance to unhook and close the KVMI channel (signaling that the
operation can proceed).

2. KVMI_EVENT_PAUSE_VCPU
------------------------

:Architectures: all
:Versions: >= 1
:Actions: CONTINUE, CRASH
:Parameters:

::

	struct kvmi_event;

:Returns:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_event_reply;

This event is sent in response to a *KVMI_VCPU_PAUSE* command and
cannot be disabled via *KVMI_VCPU_CONTROL_EVENTS*.

This event has a low priority. It will be sent after any other vCPU
introspection event and when no vCPU introspection command is queued.

3. KVMI_EVENT_HYPERCALL
-----------------------

:Architectures: x86
:Versions: >= 1
:Actions: CONTINUE, CRASH
:Parameters:

::

	struct kvmi_event;

:Returns:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_event_reply;

This event is sent on a specific user hypercall when the introspection has
been enabled for this event (see *KVMI_VCPU_CONTROL_EVENTS*).

The hypercall number must be ``KVM_HC_XEN_HVM_OP`` with the
``KVM_HC_XEN_HVM_OP_GUEST_REQUEST_VM_EVENT`` sub-function
(see hypercalls.txt).

The most useful registers describing the vCPU state can be read from
``struct kvmi_event``.

It is used by the code residing inside the introspected guest to call the
introspection tool and to report certain details about its operation. For
example, a classic antimalware remediation tool can report what it has
found during a scan.

4. KVMI_EVENT_BREAKPOINT
------------------------

:Architectures: x86
:Versions: >= 1
:Actions: CONTINUE, CRASH, RETRY
:Parameters:

::

	struct kvmi_event;
	struct kvmi_event_breakpoint {
		__u64 gpa;
		__u8 insn_len;
		__u8 padding[7];
	};

:Returns:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_event_reply;

This event is sent when a breakpoint was reached and the introspection has
been enabled for this event (see *KVMI_VCPU_CONTROL_EVENTS*).

``kvmi_event`` (with the vCPU state), the guest physical address (``gpa``)
where the breakpoint instruction is placed and the breakpoint instruction
length (``insn_len``) are sent to the introspection tool.

Some of these breakpoints could have been injected by the introspection tool,
placed in the slack space of various functions and used as notification
for when the OS or an application has reached a certain state or is
trying to perform a certain operation (like creating a process).

The *RETRY* action is used by the introspection tool for its own
breakpoints. In most cases, the tool will change the instruction pointer
before returning this action.

The *CONTINUE* action will cause the breakpoint exception to be reinjected
(the OS will handle it).

5. KVMI_EVENT_CR
----------------

:Architectures: x86
:Versions: >= 1
:Actions: CONTINUE, CRASH
:Parameters:

::

	struct kvmi_event;
	struct kvmi_event_cr {
		__u16 cr;
		__u16 padding[3];
		__u64 old_value;
		__u64 new_value;
	};

:Returns:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_event_reply;
	struct kvmi_event_cr_reply {
		__u64 new_val;
	};

This event is sent when a control register is going to be changed and the
introspection has been enabled for this event and for this specific
register (see **KVMI_VCPU_CONTROL_EVENTS**).

``kvmi_event``, the control register number, the old value and the new value
are sent to the introspection tool. The *CONTINUE* action will set the ``new_val``.

6. KVMI_EVENT_TRAP
------------------

:Architectures: x86
:Versions: >= 1
:Actions: CONTINUE, CRASH
:Parameters:

::

	struct kvmi_event;
	struct kvmi_event_trap {
		__u32 vector;
		__u32 error_code;
		__u64 cr2;
	};

:Returns:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_event_reply;

This event is sent if a previous *KVMI_VCPU_INJECT_EXCEPTION* command
took place.

``kvmi_event``, exception/interrupt number (vector), exception code
(``error_code``) and CR2 are sent to the introspection tool,
which should check if its exception has been injected or overridden.

7. KVMI_EVENT_XSETBV
--------------------

:Architectures: x86
:Versions: >= 1
:Actions: CONTINUE, CRASH
:Parameters:

::

	struct kvmi_event;

:Returns:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_event_reply;

This event is sent when the extended control register XCR0 is going
to be changed and the introspection has been enabled for this event
(see *KVMI_VCPU_CONTROL_EVENTS*).

``kvmi_event`` is sent to the introspection tool.

8. KVMI_EVENT_DESCRIPTOR
------------------------

:Architecture: x86
:Versions: >= 1
:Actions: CONTINUE, RETRY, CRASH
:Parameters:

::

	struct kvmi_event;
	struct kvmi_event_descriptor {
		__u8 descriptor;
		__u8 write;
		__u8 padding[6];
	};

:Returns:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_event_reply;

This event is sent when a descriptor table register is accessed and the
introspection has been enabled for this event (see **KVMI_VCPU_CONTROL_EVENTS**).

``kvmi_event`` and ``kvmi_event_descriptor`` are sent to the introspection tool.

``descriptor`` can be one of::

	KVMI_DESC_IDTR
	KVMI_DESC_GDTR
	KVMI_DESC_LDTR
	KVMI_DESC_TR

``write`` is 1 if the descriptor was written, 0 otherwise.

9. KVMI_EVENT_MSR
-----------------

:Architectures: x86
:Versions: >= 1
:Actions: CONTINUE, CRASH
:Parameters:

::

	struct kvmi_event;
	struct kvmi_event_msr {
		__u32 msr;
		__u32 padding;
		__u64 old_value;
		__u64 new_value;
	};

:Returns:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_event_reply;
	struct kvmi_event_msr_reply {
		__u64 new_val;
	};

This event is sent when a model specific register is going to be changed
and the introspection has been enabled for this event and for this specific
register (see **KVMI_VCPU_CONTROL_EVENTS**).

``kvmi_event``, the MSR number, the old value and the new value are
sent to the introspection tool. The *CONTINUE* action will set the ``new_val``.

10. KVMI_EVENT_PF
-----------------

:Architectures: x86
:Versions: >= 1
:Actions: CONTINUE, CRASH, RETRY
:Parameters:

::

	struct kvmi_event;
	struct kvmi_event_pf {
		__u64 gva;
		__u64 gpa;
		__u8 access;
		__u8 padding1;
		__u16 padding2;
		__u32 padding3;
	};

:Returns:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_event_reply;
	struct kvmi_event_pf_reply {
		__u64 ctx_addr;
		__u32 ctx_size;
		__u8 padding1;
		__u8 rep_complete;
		__u16 padding2;
		__u8 ctx_data[256];
	};

This event is sent when a hypervisor page fault occurs due to a failed
permission checks, the introspection has been enabled for this event
(see *KVMI_VCPU_CONTROL_EVENTS*) and the event was generated for a
page in which the introspection tool has shown interest (ie. has
previously touched it by adjusting the spte permissions; see
*KVMI_VM_SET_PAGE_ACCESS*).

These permissions can be used by the introspection tool to guarantee
the purpose of code areas inside the guest (code, rodata, stack, heap
etc.) Each attempt at an operation unfitting for a certain memory
range (eg. execute code in heap) triggers a page fault and gives the
introspection tool the chance to audit the code attempting the operation.

``kvmi_event`` (with the vCPU state), guest virtual address (``gva``)
if available or -1/UNMAPPED_GVA, guest physical address (``gpa``)
and the ``access`` flags (e.g. KVMI_PAGE_ACCESS_R) are sent to the
introspection tool.

In case of a restricted read access, the guest address is the location
of the memory being read. On write access, the guest address is the
location of the memory being written. On execute access, the guest
address is the location of the instruction being executed
(``gva == kvmi_event.arch.regs.rip``).

In the current implementation, most of these events are sent during
emulation. If the page fault has set more than one access bit
(e.g. r-x/-rw), the introspection tool may receive more than one
KVMI_PF_EVENT and the order depends on the KVM emulator. Another cause
of multiple events is when the page fault is triggered on access crossing
the page boundary.

The *CONTINUE* action will continue the page fault handling via emulation.
If ``rep_complete`` is 1, the REP prefixed instruction should be emulated
just once (or at least no other *KVMI_EVENT_PF* event should be sent
for the current instruction).
If ``ctx_size > 0`` and ``kvmi_event_pf.gva`` is in the range of
``[ctx_addr, ctx_addr+ctx_size)``, the emulation will continue
with custom input from ``ctx_data[0 .. ctx_size-1]``. The use of custom
input is to trick the guest software into believing it has read certain
data, in order to hide the content of certain memory areas (eg. hide
injected code from integrity checkers).

The *RETRY* action is used by the introspection tool to retry the
execution of the current instruction, usually because it changed the
instruction pointer or the page restrictions.

11. KVMI_EVENT_SINGLESTEP
-------------------------

:Architectures: x86
:Versions: >= 1
:Actions: CONTINUE, CRASH
:Parameters:

::

	struct kvmi_event;

:Returns:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_event_reply;
	struct kvmi_event_singlestep {
		__u8 failed;
		__u8 padding[7];
	};

This event is sent when the current instruction has been executed or the
singlestep failed and the introspection has been enabled for this event
(see **KVMI_VCPU_CONTROL_EVENTS**).

12. KVMI_EVENT_CREATE_VCPU
--------------------------

:Architectures: all
:Versions: >= 1
:Actions: CONTINUE, CRASH
:Parameters:

::

	struct kvmi_event;

:Returns:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_event_reply;

This event is sent when a new vCPU is created and the introspection has
been enabled for this event (see *KVMI_VM_CONTROL_EVENTS*).

13. KVMI_EVENT_CMD_ERROR
------------------------

:Architecture: all
:Versions: >= 1
:Actions: none
:Parameters:

::

	struct kvmi_event;
	struct kvmi_event_cmd_error {
		__s32 err;
		__u32 msg_seq;
		__u16 msg_id;
		__u16 padding[3];
	};

:Returns: none

This event is sent when the an introspection command fails while the
replies are disabled, but the introspection tool requested to be
notified on failures (see `flag` from *KVMI_VM_CONTROL_CMD_RESPONSE*).

14. KVMI_EVENT_CPUID
--------------------

:Architecture: x86
:Version: >= 1
:Actions: CONTINUE, CRASH
:Parameters:

::

	struct kvmi_event;
	struct kvmi_event_cpuid {
		__u32 function;
		__u32 index;
		__u8  insn_length;
		__u8  padding1[3];
		__u32 padding2;
	};

:Returns:

	struct kvmi_vcpu_hdr;
	struct kvmi_event_reply;

This event is sent when a cpuid instructions is executed and the 
introspection has been enabled for this event (see *KVMI_VM_CONTROL_EVENTS*).
