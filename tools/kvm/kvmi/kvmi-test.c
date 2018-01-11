/*
 * Copyright (C) 2017-2018 Bitdefender S.R.L.
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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>

#include <kvmi/libkvmi.h>

#define CR3 3
#define CR4 4

#define MSR_STAR 0xc0000081

#define MAX_CPU 8

struct event {
	unsigned int  seq;
	unsigned int  size;
	unsigned char data[KVMI_MAX_MSG_SIZE];
} queue[MAX_CPU] = { 0 };

unsigned int events = 0;

static void die( const char *msg )
{
	perror( msg );
	exit( 1 );
}

static bool valid_event_size( unsigned int size )
{
	return ( size < sizeof( KVMI_MAX_MSG_SIZE ) && size >= sizeof( struct kvmi_event ) );
}

static bool can_queue_event( unsigned int vcpu )
{
	return ( vcpu < sizeof( queue ) / sizeof( queue[0] ) && queue[vcpu].size == 0 );
}

static int new_event( int fd, unsigned int seq, unsigned int size, void *ctx )
{
	unsigned char      data[KVMI_MAX_MSG_SIZE];
	struct kvmi_event *ev = ( struct kvmi_event * )data;
	int                k;

	if ( !valid_event_size( size ) || kvmi_read_event_data( fd, &data, size ) ) {
		fprintf( stderr, "kvmi_read_event_data(%d, %d) %p", seq, size, ctx );
		die( NULL );
	}

	k = ev->vcpu;
	if ( !can_queue_event( k ) ) {
		fprintf( stderr, "can't queue the event for vcpu %d\n", k );
		exit( 1 );
	}

	memcpy( queue[k].data, data, size );
	queue[k].seq  = seq;
	queue[k].size = size;

	return 0;
}

static bool pop_event( unsigned int *seq, unsigned int *size, unsigned char *data )
{
	size_t k;
	for ( k = 0; k < sizeof( queue ) / sizeof( queue[0] ); k++ )
		if ( queue[k].size ) {
			*seq  = queue[k].seq;
			*size = queue[k].size;
			memcpy( data, queue[k].data, *size );
			queue[k].size = 0;
			return true;
		}
	return false;
}

static bool wait_event( int fd, unsigned int *seq, unsigned int *size, unsigned char *data )
{
	struct pollfd p = { 0 };
	int           r;

	p.fd     = fd;
	p.events = POLLIN;

	do {
		r = poll( &p, 1, -1 );
	} while ( r < 0 && errno == EINTR );

	if ( !( r == 1 && ( p.revents & POLLIN ) ) )
		return false;

	if ( kvmi_read_event( fd, data, *size, seq ) )
		die( "kvmi_read_event" );

	return true;
}

static void reply_continue( int fd, unsigned int seq, void *_rpl, size_t rpl_size )
{
	struct kvmi_event_reply *rpl = _rpl;

	rpl->action = KVMI_EVENT_ACTION_CONTINUE;

	if ( kvmi_reply_event( fd, seq, rpl, rpl_size ) )
		die( "kvmi_reply_event" );
}

static void handle_cr_event( int fd, unsigned int seq, unsigned int size, struct kvmi_event *ev )
{
	struct kvmi_event_cr *cr = ( struct kvmi_event_cr * )( ev + 1 );
	struct {
		struct kvmi_event_reply common;
		struct kvmi_event_cr_reply {
			__u64 new_val;
		} cr;
	} rpl = { 0 };

	if ( size < sizeof( *ev ) + sizeof( *cr ) ) {
		fprintf( stderr, "CR: invalid size: %u (expected %zu)\n", size, sizeof( *ev ) + sizeof( *cr ) );
		exit( 1 );
	}

	printf( "CR%d %llx -> %llx\n", cr->cr, cr->old_value, cr->new_value );

	rpl.cr.new_val = cr->new_value;
	reply_continue( fd, seq, &rpl, sizeof( rpl ) );
}

static void handle_msr_event( int fd, unsigned int seq, unsigned int size, struct kvmi_event *ev )
{
	struct kvmi_event_msr *msr = ( struct kvmi_event_msr * )( ev + 1 );
	struct {
		struct kvmi_event_reply common;
		struct kvmi_event_msr_reply {
			__u64 new_val;
		} msr;
	} rpl = { 0 };

	if ( size < sizeof( *ev ) + sizeof( *msr ) ) {
		fprintf( stderr, "MSR: invalid size: %u (expected %zu)\n", size, sizeof( *ev ) + sizeof( *msr ) );
		exit( 1 );
	}

	printf( "MSR: %x %llx -> %llx\n", msr->msr, msr->old_value, msr->new_value );

	rpl.msr.new_val = msr->new_value;
	reply_continue( fd, seq, &rpl, sizeof( rpl ) );
}

static void handle_pause_vcpu_event( int fd, unsigned int seq, struct kvmi_event *ev )
{
	bool                    first_time = ( events == 0 && ev->vcpu == 0 );
	struct kvmi_event_reply rpl        = { 0 };

	printf( "PAUSE\n" );

	if ( first_time ) {
		bool enable = true;

		events |= KVMI_EVENT_CR | KVMI_EVENT_MSR;

		if ( kvmi_control_events( fd, ev->vcpu, events ) )
			die( "kvmi_control_events" );

		if ( kvmi_control_cr( fd, CR3, enable ) )
			die( "kvmi_control_cr(3)" );

		if ( kvmi_control_cr( fd, CR4, enable ) )
			die( "kvmi_control_cr(4)" );

		if ( kvmi_control_msr( fd, MSR_STAR, enable ) )
			die( "kvmi_control_msr(STAR)" );
	}

	reply_continue( fd, seq, &rpl, sizeof( rpl ) );
}

static void handle_event( int fd )
{
	unsigned char      data[KVMI_MAX_MSG_SIZE];
	struct kvmi_event *ev = ( struct kvmi_event * )data;
	unsigned int       seq, size;

	if ( !pop_event( &seq, &size, data ) ) {
		size = sizeof( data );
		if ( !wait_event( fd, &seq, &size, data ) )
			return;
	}

	switch ( ev->event ) {
		case KVMI_EVENT_CR:
			handle_cr_event( fd, seq, size, ev );
			break;
		case KVMI_EVENT_MSR:
			handle_msr_event( fd, seq, size, ev );
			break;
		case KVMI_EVENT_PAUSE_VCPU:
			handle_pause_vcpu_event( fd, seq, ev );
			break;
		default:
			fprintf( stderr, "Unknown event %d\n", ev->event );
			exit( 1 );
	}
}

static void pause_first_vcpu( int fd )
{
	unsigned short vcpu = 0;
	int            err;

	do {
		err = kvmi_pause_vcpu( fd, vcpu );
		if ( err ) {
			perror( "kvmi_pause_vcpu" );
			if ( errno != EINVAL )
				exit( 1 );
			usleep( 100 );
		}
	} while ( err );
}

static int new_guest( int fd, unsigned char ( *uuid )[16], void *ctx )
{
	int k;

	printf( "New guest: " );

	for ( k = 0; k < 16; k++ )
		printf( "%.2x ", ( *uuid )[k] );
	printf( "fd:%d ctx:%p\n", fd, ctx );

	pause_first_vcpu( fd );

	while ( 1 )
		handle_event( fd );

	/* We should return from this callback to allow other connections to be accepted */

	return 0;
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

	kvmi_set_event_cb( new_event, NULL ); /* global */

	if ( atoi( argv[1] ) > 0 ) {
		ctx = kvmi_init_v_sock( atoi( argv[1] ), new_guest, NULL );
	} else {
		ctx = kvmi_init_un_sock( argv[1], new_guest, NULL );
	}

	if ( !ctx ) {
		perror( "kvmi_init" );
		exit( 1 );
	}

	sleep( 600 );

	kvmi_uninit( ctx );

	return 0;
}
