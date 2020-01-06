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
	};

Returns the introspection API version.

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

	KVMI_EVENT_HYPERCALL

When an event is enabled, the introspection tool is notified and it
must reply with: continue, retry, crash, etc. (see **Events** below).

The *KVMI_EVENT_PAUSE_VCPU* event is always allowed,
because it is triggered by the *KVMI_VCPU_PAUSE* command.

The *KVMI_EVENT_UNHOOK* event is controlled
by the *KVMI_VM_CONTROL_EVENTS* command.

:Errors:

* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EINVAL - the event ID is invalid/unknown (use *KVMI_VM_CHECK_EVENT* first)
* -KVM_EINVAL - padding is not zero
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_EPERM - the access is restricted by the host

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

Events
======

All introspection events (VM or vCPU related) are sent
using the *KVMI_EVENT* message id. No event will be sent unless
it is explicitly enabled (see *KVMI_VM_CONTROL_EVENTS* and *KVMI_VCPU_CONTROL_EVENTS*)
or requested (eg. *KVMI_EVENT_PAUSE_VCPU*).

The *KVMI_EVENT_UNHOOK* event doesn't have a reply and share the kvmi_event
structure, for consistency with the vCPU events.

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

It is used by the code residing inside the introspected guest to call the
introspection tool and to report certain details about its operation. For
example, a classic antimalware remediation tool can report what it has
found during a scan.
