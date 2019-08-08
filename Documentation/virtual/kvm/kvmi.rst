=========================================================
KVMI - The kernel virtual machine introspection subsystem
=========================================================

The KVM introspection subsystem provides a facility for applications running
on the host or in a separate VM, to control the execution of other VM-s
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

Memory access safety
--------------------

The KVMI API gives access to the entire guest physical address space but
provides no information on which parts of it are system RAM and which are
device-specific memory (DMA, emulated MMIO, reserved by a passthrough
device etc.). It is up to the user to determine, using the guest operating
system data structures, the areas that are safe to access (code, stack, heap
etc.).
