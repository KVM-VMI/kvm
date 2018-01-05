/*
 * Copyright (C) 2017-2018 Bitdefender S.R.L.
 *
 * The KVMI Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * The KVMI Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the GNU C Library; if not, see
 * <http://www.gnu.org/licenses/>
 */
#ifndef __LIBKVMI_H_INCLUDED__
#define __LIBKVMI_H_INCLUDED__

#include <stdbool.h>

/* if missing from linux/kernel.h */
#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF( t, f ) ( sizeof( ( ( t * )0 )->f ) )
#endif

#include <linux/kvmi.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int   kvmi_init( int ( *cb )( int fd, unsigned char ( *uuid )[16], void *ctx ), void *cb_ctx );
void  kvmi_uninit( void );
void  kvmi_set_event_cb( int ( *cb )( int fd, unsigned int seq, unsigned int size, void *ctx ), void *cb_ctx );
int   kvmi_get_version( int fd, unsigned int *version );
int   kvmi_control_events( int fd, unsigned short vcpu, unsigned int events );
int   kvmi_control_cr( int fd, unsigned int cr, bool enable );
int   kvmi_control_msr( int fd, unsigned int msr, bool enable );
int   kvmi_get_page_access( int fd, unsigned short vcpu, unsigned long long int gpa, unsigned char *access );
int   kvmi_set_page_access( int fd, unsigned short vcpu, unsigned long long int *gpa, unsigned char *access,
                            unsigned short count );
int   kvmi_pause_vcpu( int fd, unsigned short vcpu );
int   kvmi_get_vcpu_count( int fd, unsigned short *count );
int   kvmi_get_tsc_speed( int fd, unsigned long long int *speed );
int   kvmi_get_cpuid( int fd, unsigned short vcpu, unsigned int function, unsigned int index, unsigned int *eax,
                      unsigned int *ebx, unsigned int *ecx, unsigned int *edx );
int   kvmi_get_xsave( int fd, unsigned short vcpu, void *buffer, size_t bufSize );
int   kvmi_inject_page_fault( int fd, unsigned short vcpu, unsigned long long int gva, unsigned int error );
int   kvmi_inject_breakpoint( int fd, unsigned short vcpu );
int   kvmi_read_physical( int fd, unsigned long long int gpa, void *buffer, size_t size );
int   kvmi_write_physical( int fd, unsigned long long int gpa, const void *buffer, size_t size );
int   kvmi_open_memmap( void );
void *kvmi_map_physical_page( int fd, int memfd, unsigned long long int gpa );
int   kvmi_unmap_physical_page( int fd, int memfd, void *addr );
int   kvmi_get_registers( int fd, unsigned short vcpu, struct kvm_regs *regs, struct kvm_sregs *sregs,
                          struct kvm_msrs *msrs, unsigned int *mode );
int   kvmi_set_registers( int fd, unsigned short vcpu, const struct kvm_regs *regs );
int   kvmi_shutdown_guest( int fd );
int   kvmi_reply_event( int fd, unsigned int msg_seq, const void *data, unsigned int data_size );
int   kvmi_read_event_header( int fd, unsigned int *id, unsigned int *size, unsigned int *seq );
int   kvmi_read_event_data( int fd, void *buf, unsigned int size );
int   kvmi_read_event( int fd, void *buf, unsigned int max_size, unsigned int *seq );

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LIBKVMI_H_INCLUDED__ */
