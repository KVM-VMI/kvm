/*
 * Copyright (C) 2017-2019 Bitdefender S.R.L.
 *
 * The program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * The program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * http://www.gnu.org/licenses
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <kvmi/libkvmi.h>

#define CR3 3
#define CR4 4

#define MSR_STAR 0xc0000081

static unsigned int events;
static void *Dom;

static const char *access_str[] = {
	"---", "r--", "-w-", "rw-", "--x", "r-x", "-wx", "rwx",
};

static void die( const char *msg )
{
	perror( msg );
	exit( 1 );
}

static void reply_continue( void *dom, struct kvmi_dom_event *ev, void *_rpl, size_t rpl_size )
{
	struct kvmi_event_reply *rpl = _rpl;

	rpl->action = KVMI_EVENT_ACTION_CONTINUE;
	rpl->event  = ev->event.common.event;

	printf( "Reply with CONTINUE\n" );

	if ( kvmi_reply_event( dom, ev->seq, rpl, rpl_size ) )
		die( "kvmi_reply_event" );
}

static void reply_retry( void *dom, struct kvmi_dom_event *ev, void *_rpl, size_t rpl_size )
{
	struct kvmi_event_reply *rpl = _rpl;

	rpl->action = KVMI_EVENT_ACTION_RETRY;
	rpl->event  = ev->event.common.event;

	printf( "Reply with RETRY\n" );

	if ( kvmi_reply_event( dom, ev->seq, rpl, rpl_size ) )
		die( "kvmi_reply_event" );
}

static void handle_cr_event( void *dom, struct kvmi_dom_event *ev )
{
	struct kvmi_event_cr *cr = &ev->event.cr;
	struct {
		struct kvmi_event_reply common;
		struct kvmi_event_cr_reply {
			__u64 new_val;
		} cr;
	} rpl = { 0 };

	printf( "CR%d %llx -> %llx\n", cr->cr, cr->old_value, cr->new_value );

	rpl.cr.new_val = cr->new_value;
	reply_continue( dom, ev, &rpl, sizeof( rpl ) );
}

static void handle_msr_event( void *dom, struct kvmi_dom_event *ev )
{
	struct kvmi_event_msr *msr = &ev->event.msr;
	struct {
		struct kvmi_event_reply common;
		struct kvmi_event_msr_reply {
			__u64 new_val;
		} msr;
	} rpl = { 0 };

	printf( "MSR: %x %llx -> %llx\n", msr->msr, msr->old_value, msr->new_value );

	rpl.msr.new_val = msr->new_value;
	reply_continue( dom, ev, &rpl, sizeof( rpl ) );
}

static void handle_pause_vcpu_event( void *dom, struct kvmi_dom_event *ev )
{
	bool                    first_time = ( events == 0 );
	struct kvmi_event_reply rpl        = { 0 };
	unsigned int            vcpu       = ev->event.common.vcpu;

	printf( "PAUSE vCPU %u\n", vcpu );

	if ( first_time ) {
		bool enable = true;

		events |= KVMI_EVENT_CR_FLAG | KVMI_EVENT_MSR_FLAG | KVMI_EVENT_PF_FLAG;

		printf( "Enabling CR, MSR and PF events for vCPU%d (0x%x)\n", vcpu, events );

		if ( kvmi_control_events( dom, vcpu, events ) )
			die( "kvmi_control_events" );

		printf( "Enabling CR3 events...\n" );

		if ( kvmi_control_cr( dom, vcpu, CR3, enable ) )
			die( "kvmi_control_cr(3)" );

		printf( "Enabling CR4 events...\n" );

		if ( kvmi_control_cr( dom, vcpu, CR4, enable ) )
			die( "kvmi_control_cr(4)" );

		printf( "Enabling MSR_STAR events...\n" );

		if ( kvmi_control_msr( dom, vcpu, MSR_STAR, enable ) )
			die( "kvmi_control_msr(STAR)" );
	}

	reply_continue( dom, ev, &rpl, sizeof( rpl ) );
}

static __u8 get_page_access( void *dom, __u16 vcpu, __u64 gpa )
{
	unsigned char access;

	printf( "Get page access vCPU:%u gpa:%llx\n", vcpu, gpa );

	if ( kvmi_get_page_access( dom, vcpu, gpa, &access ) )
		die( "kvmi_set_page_access" );

	printf( "Access is %s (%x)\n", access_str[access & 7], access );

	return access;
}

static void set_page_access( void *dom, __u16 vcpu, __u64 gpa, __u8 access )
{
	printf( "Set page access vCPU:%u gpa:%llx access:%s (%x)\n", vcpu, gpa, access_str[access & 7], access );

	if ( kvmi_set_page_access( dom, vcpu, &gpa, &access, 1 ) )
		die( "kvmi_set_page_access" );
}

static bool write_protect_page( void *dom, __u16 vcpu, __u64 gpa )
{
	__u8 access = get_page_access( dom, vcpu, gpa );

	if ( access & KVMI_PAGE_ACCESS_W ) {
		access &= ~KVMI_PAGE_ACCESS_W;
		set_page_access( dom, vcpu, gpa, access );

		return true;
	}

	return false;
}

static void maybe_start_pf_test( void *dom, struct kvmi_dom_event *ev )
{
	static bool started;
	__u64       cr3  = ev->event.common.sregs.cr3;
	__u16       vcpu = ev->event.common.vcpu;
	__u64       pt   = cr3 & ~0xfff;

	if ( started || !pt )
		return;

	printf( "Starting #PF test with CR3:%llx\n", cr3 );

	for ( __u64 end = pt + 10 * 4096; pt < end; pt += 4096 )
		if ( write_protect_page( dom, vcpu, pt ) )
			started = true;
}

static void handle_pf_event( void *dom, struct kvmi_dom_event *ev )
{
	struct kvmi_event_pf *pf   = &ev->event.page_fault;
	__u16                 vcpu = ev->event.common.vcpu;
	struct {
		struct kvmi_event_reply    common;
		struct kvmi_event_pf_reply pf;
	} rpl = {};

	printf( "PF vCPU %u gva:%llx gpa:%llx mode:%s (%x)\n", vcpu, pf->gva, pf->gpa, access_str[pf->mode & 7],
	        pf->mode );

	if ( pf->mode & KVMI_PAGE_ACCESS_W ) {
		__u8 access = get_page_access( dom, vcpu, pf->gpa );

		access |= KVMI_PAGE_ACCESS_W;

		set_page_access( dom, vcpu, pf->gpa, access );
	}

	reply_retry( dom, ev, &rpl, sizeof( rpl ) );
}

static void handle_event( void *dom, struct kvmi_dom_event *ev )
{
	unsigned int id = ev->event.common.event;

	switch ( id ) {
		case KVMI_EVENT_CR:
			maybe_start_pf_test( dom, ev );
			handle_cr_event( dom, ev );
			break;
		case KVMI_EVENT_MSR:
			handle_msr_event( dom, ev );
			break;
		case KVMI_EVENT_PAUSE_VCPU:
			maybe_start_pf_test( dom, ev );
			handle_pause_vcpu_event( dom, ev );
			break;
		case KVMI_EVENT_PF:
			handle_pf_event( dom, ev );
			break;
		default:
			fprintf( stderr, "Unknown event %d\n", id );
			exit( 1 );
	}
}

static void pause_vm( void *dom )
{
	unsigned int count = 0;

	printf( "Sending the pause command...\n" );

	if ( kvmi_pause_all_vcpus( dom, &count ) )
		die( "kvmi_pause_all_vcpus" );

	printf( "We should receive %u pause events\n", count );
}

static int new_guest( void *dom, unsigned char ( *uuid )[16], void *ctx )
{
	int k;

	printf( "New guest: " );

	for ( k = 0; k < 16; k++ )
		printf( "%.2x ", ( *uuid )[k] );

	printf( "fd:%d ctx:%p\n", kvmi_connection_fd( dom ), ctx );

	pause_vm( dom );

	Dom = dom;

	return 0;
}

static int new_handshake( const struct kvmi_qemu2introspector *qemu, struct kvmi_introspector2qemu *intro, void *ctx )
{
	printf( "New handshake\n" );
	return 0;
}

static void log_cb( kvmi_log_level level, const char *s, void *ctx )
{
	printf( "level=%d: %s\n", level, s );
}

int main( int argc, char **argv )
{
	void *ctx;

	if ( argc != 2 ) {
		printf( "Usage:\n"
		        "	%s PathToSocket\n"
		        "	%s VSockPortNumber\n",
		        argv[0], argv[0] );
		return 1;
	}

	kvmi_set_log_cb( log_cb, NULL );

	if ( atoi( argv[1] ) > 0 ) {
		ctx = kvmi_init_vsock( atoi( argv[1] ), new_guest, new_handshake, NULL );
	} else {
		ctx = kvmi_init_unix_socket( argv[1], new_guest, new_handshake, NULL );
	}

	if ( !ctx ) {
		perror( "kvmi_init" );
		exit( 1 );
	}

	printf( "Waiting...\n" );

	while ( !Dom )
		sleep( 1 );

	while ( 1 ) {
		struct kvmi_dom_event *ev;

		printf( "Waiting...\n" );

		if ( kvmi_wait_event( Dom, 30*1024 ) ) {
			if ( errno == ETIMEDOUT ) {
				printf( "No event.\n" );
				continue;
			}
			die( "kvmi_wait_event" );
		}

		printf( "Pop event\n" );

		if ( kvmi_pop_event( Dom, &ev ) )
			die( "kvmi_pop_event" );

		handle_event( Dom, ev );
	}

	kvmi_uninit( ctx );

	return 0;
}
