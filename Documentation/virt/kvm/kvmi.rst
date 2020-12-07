.. SPDX-License-Identifier: GPL-2.0

=========================================================
KVMI - The kernel virtual machine introspection subsystem
=========================================================

The KVM introspection subsystem provides a facility for applications running
on the host or in a separate VM, to control the execution of any running VMs
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

The initial connection is established by an application running on the
host (eg. QEMU) that connects to the introspection tool and after a
handshake the file descriptor is passed to the host kernel making all
further communication take place between it and the introspection tool.

The socket protocol allows for commands and events to be multiplexed over
the same connection. As such, it is possible for the introspection tool to
receive an event while waiting for the result of a command. Also, it can
send a command while the host kernel is waiting for a reply to an event.

The kernel side of the socket communication is blocking and will wait
for an answer from its peer indefinitely or until the guest is powered
off (killed), restarted or the peer goes away, at which point it will
wake up and properly cleanup as if the introspection subsystem has never
been used on that guest (if requested). Obviously, whether the guest can
really continue normal execution depends on whether the introspection
tool has made any modifications that require an active KVMI channel.

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

Other error codes can be returned during message handling, but for
some errors (incomplete messages, wrong sequence numbers, socket errors
etc.) the socket will be closed. The device manager should reconnect.

When a vCPU thread sends an introspection event, it will wait (and handle
any related introspection command) until it gets the event reply::

   Host kernel               Introspection tool
   -----------               ------------------
   event 1 ->
                             <- command 1
   command 1 reply ->
                             <- command 2
   command 2 reply ->
                             <- event 1 reply

As it can be seen below, the wire protocol specifies occasional padding. This
is to permit working with the data by directly using C structures or to round
the structure size to a multiple of 8 bytes (64bit) to improve the copy
operations that happen during ``recvmsg()`` or ``sendmsg()``. The members
should have the native alignment of the host. All padding must be
initialized with zero otherwise the respective command will fail with
-KVM_EINVAL.

To describe the commands/events, we reuse some conventions from api.rst:

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

In the end, the device manager will pass the file descriptor (plus
the allowed commands/events) to KVM. It will detect when the socket is
shutdown and it will reinitiate the handshake.

Once the file descriptor reaches KVM, the introspection tool should
use the *KVMI_GET_VERSION* command to get the API version and/or the
*KVMI_VM_CHECK_COMMAND* and *KVMI_VM_CHECK_EVENT* commands to see which
commands/events are allowed for this guest. The error code -KVM_EPERM
will be returned if the introspection tool uses a command or tries to
enable an event which is disallowed.

Unhooking
---------

During a VMI session it is possible for the guest to be patched and for
some of these patches to "talk" with the introspection tool. It thus
becomes necessary to remove them before the guest is suspended, moved
(migrated) or a snapshot with memory is created.

The actions are normally performed by the device manager. In the case
of QEMU, it will use the *KVM_INTROSPECTION_PREUNHOOK* ioctl to trigger
the *KVMI_VM_EVENT_UNHOOK* event and wait for a limited amount of time (a
few seconds) for a confirmation that is OK to proceed. The introspection
tool will close the connection to signal this.

Live migrations
---------------

Before the live migration takes place, the introspection tool has to be
notified and have a chance to unhook (see **Unhooking**).

The QEMU instance on the receiving end, if configured for KVMI, will need
to establish a connection to the introspection tool after the migration
has been completed.

Obviously, this creates a window in which the guest is not introspected.
The user has to be aware of this detail. Future introspection technologies
can choose not to disconnect and instead transfer the necessary context
to the introspection tool at the migration destination via a separate
channel.

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

The vCPU commands start with::

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
		__u32 max_msg_size;
	};

Returns the introspection API version and the largest accepted message
size (useful for variable length messages).

This command is always allowed and successful.

The messages used for introspection commands/events might be extended
in future versions and while the kernel will accept commands with
shorter messages (older versions) or larger messages (newer versions,
ignoring the extra information), it will not accept event replies with
larger messages.

The introspection tool should use this command to identify the features
supported by the kernel side and what messages must be used for event
replies.

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

Checks if the command specified by ``id`` is supported and allowed.

This command is always allowed.

:Errors:

* -KVM_ENOENT - the command specified by ``id`` is unsupported
* -KVM_EPERM - the command specified by ``id`` is disallowed
* -KVM_EINVAL - the padding is not zero

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

Checks if the event specified by ``id`` is supported and allowed.

This command is always allowed.

:Errors:

* -KVM_ENOENT - the event specified by ``id`` is unsupported
* -KVM_EPERM - the event specified by ``id`` is disallowed
* -KVM_EINVAL - the padding is not zero

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

	KVMI_VM_EVENT_UNHOOK

:Errors:

* -KVM_EINVAL - the padding is not zero
* -KVM_EINVAL - the event ID is unknown (use *KVMI_VM_CHECK_EVENT* first)
* -KVM_EPERM - the access is disallowed (use *KVMI_VM_CHECK_EVENT* first)

6. KVMI_VM_READ_PHYSICAL
------------------------

:Architectures: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vm_read_physical {
		__u64 gpa;
		__u16 size;
		__u16 padding1;
		__u32 padding2;
	};

:Returns:

::

	struct kvmi_error_code;
	__u8 data[0];

Reads from the guest memory.

Currently, the size must be non-zero and the read must be restricted to
one page (offset + size <= PAGE_SIZE).

:Errors:

* -KVM_ENOENT - the guest page doesn't exists
* -KVM_EINVAL - the specified gpa/size pair is invalid
* -KVM_EINVAL - the padding is not zero

7. KVMI_VM_WRITE_PHYSICAL
-------------------------

:Architectures: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vm_write_physical {
		__u64 gpa;
		__u16 size;
		__u16 padding1;
		__u32 padding2;
		__u8  data[0];
	};

:Returns:

::

	struct kvmi_error_code

Writes into the guest memory.

Currently, the size must be non-zero and the write must be restricted to
one page (offset + size <= PAGE_SIZE).

:Errors:

* -KVM_ENOENT - the guest page doesn't exists
* -KVM_EINVAL - the specified gpa/size pair is invalid
* -KVM_EINVAL - the padding is not zero

8. KVMI_VCPU_GET_INFO
---------------------

:Architectures: x86
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

* -KVM_EINVAL - the padding is not zero
* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EAGAIN - the selected vCPU can't be introspected yet

9. KVMI_VM_PAUSE_VCPU
---------------------

:Architectures: all
:Versions: >= 1
:Parameters:

::

	struct kvmi_vm_pause_vcpu {
		__u16 vcpu;
		__u8 wait;
		__u8 padding1;
		__u32 padding2;
	};

:Returns:

::

	struct kvmi_error_code;

Kicks the vCPU out of guest.

If `wait` is 1, the command will wait for vCPU to acknowledge the IPI.

The vCPU will handle the pending commands/events and send the
*KVMI_VCPU_EVENT_PAUSE* event (one for every successful *KVMI_VM_PAUSE_VCPU*
command) before returning to guest.

:Errors:

* -KVM_EINVAL - the padding is not zero
* -KVM_EINVAL - the selected vCPU is invalid
* -KVM_EAGAIN - the selected vCPU can't be introspected yet
* -KVM_EBUSY  - the selected vCPU has too many queued
                *KVMI_VCPU_EVENT_PAUSE* events
* -KVM_EPERM  - the *KVMI_VCPU_EVENT_PAUSE* event is disallowed

Events
======

The VM introspection events are sent using the KVMI_VM_EVENT message id.
No event is sent unless it is explicitly enabled.
The message data begins with a common structure having the event id::

	struct kvmi_event_hdr {
		__u16 event;
		__u16 padding[3];
	};

The vCPU introspection events are sent using the KVMI_VCPU_EVENT message id.
No event is sent unless it is explicitly enabled or requested
(e.g. *KVMI_VCPU_EVENT_PAUSE*).
A vCPU event begins with a common structure having the size of the
structure and the vCPU index::

	struct kvmi_vcpu_event {
		__u16 size;
		__u16 vcpu;
		__u32 padding;
		struct kvmi_vcpu_event_arch arch;
	};

On x86::

	struct kvmi_vcpu_event_arch {
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

A vCPU event reply begins with two common structures::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_event_reply {
		__u8 action;
		__u8 event;
		__u16 padding1;
		__u32 padding2;
	};

All events accept the KVMI_EVENT_ACTION_CRASH action, which stops the
guest ungracefully, but as soon as possible.

Most events accept the KVMI_EVENT_ACTION_CONTINUE action, which
means that KVM will continue handling the event.

Some events accept the KVMI_EVENT_ACTION_RETRY action, which means that
KVM will stop handling the event and re-enter in guest.

Specific event data can follow these common structures.

1. KVMI_VM_EVENT_UNHOOK
-----------------------

:Architectures: all
:Versions: >= 1
:Actions: none
:Parameters:

::

	struct kvmi_event_hdr;

:Returns: none

This event is sent when the device manager has to pause/stop/migrate
the guest (see **Unhooking**) and the introspection has been enabled for
this event (see **KVMI_VM_CONTROL_EVENTS**). The introspection tool has
a chance to unhook and close the introspection socket (signaling that
the operation can proceed).

2. KVMI_VCPU_EVENT_PAUSE
------------------------

:Architectures: all
:Versions: >= 1
:Actions: CONTINUE, CRASH
:Parameters:

::

	struct kvmi_event_hdr;
	struct kvmi_vcpu_event;

:Returns:

::

	struct kvmi_vcpu_hdr;
	struct kvmi_vcpu_event_reply;

This event is sent in response to a *KVMI_VCPU_PAUSE* command and
cannot be controlled with *KVMI_VCPU_CONTROL_EVENTS*.
Because it has a low priority, it will be sent after any other vCPU
introspection event and when no other vCPU introspection command is
queued.
