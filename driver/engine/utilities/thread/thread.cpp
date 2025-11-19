#include "thread.hpp"

#include "../oxorany/oxorany_include.h"
#include "../offsets/offsets.hpp"
#include "../encrypt/encrypt.hpp"
#include "../kernel/kernel.hpp"

namespace utilities::thread {

	void spoof( void* address, void** save, void* target ) {
		*save = *reinterpret_cast< void** >( address );
		*reinterpret_cast< void** >( address ) = target;
	}

	bool hide( ) {
		auto ntoskrnl = reinterpret_cast< void* >( kernel::get_module( e("ntoskrnl.exe") ) + o( 0x171b8e ) );
		if ( !ntoskrnl )
			return o( false );

		auto current_thread = reinterpret_cast< uint64_t >( KeGetCurrentThread( ) );
		if (!current_thread)
			return false;

		auto create_time = reinterpret_cast< void* >( current_thread + offsets::g_create_time );
		auto start_address = reinterpret_cast< void* >( current_thread + offsets::g_start_address );
		auto win32_start_address = reinterpret_cast< void* >( current_thread + offsets::g_win32_start_address );
		auto kernel_stack = reinterpret_cast< void* >( current_thread + offsets::g_kernel_stack );
		auto cid = reinterpret_cast< void* >( current_thread + offsets::g_cid );
		auto exit_status = reinterpret_cast< void* >( current_thread + offsets::g_exit_status );

		spoof( create_time, &saved_create_time, reinterpret_cast< void* >( o( 1700039443 ) ) );
		spoof( start_address, &saved_start_address, ntoskrnl );
		spoof( win32_start_address, &saved_win32_start_address, ntoskrnl );
		spoof( kernel_stack, &saved_kernel_stack );
		spoof( cid, &saved_cid );
		spoof( exit_status, &saved_exit_status );

		return o( true );
	}

	bool terminate( ) {
		auto current_thread = reinterpret_cast< uint64_t >( KeGetCurrentThread( ) );
		if ( !current_thread )	
			return o( false );

		auto create_time = reinterpret_cast< void* >( current_thread + offsets::g_create_time );
		auto start_address = reinterpret_cast< void* >( current_thread + offsets::g_start_address );
		auto win32_start_address = reinterpret_cast< void* >( current_thread + offsets::g_win32_start_address );
		auto kernel_stack = reinterpret_cast< void* >( current_thread + offsets::g_kernel_stack );
		auto cid = reinterpret_cast< void* >( current_thread + offsets::g_cid );
		auto exit_status = reinterpret_cast< void* >( current_thread + offsets::g_exit_status );

		*reinterpret_cast< void** >( create_time ) = saved_create_time;
		*reinterpret_cast< void** >( start_address ) = saved_start_address;
		*reinterpret_cast< void** >( win32_start_address ) = saved_win32_start_address;
		*reinterpret_cast< void** >( kernel_stack ) = saved_kernel_stack;
		*reinterpret_cast< void** >( cid ) = saved_cid;
		*reinterpret_cast< void** >( exit_status ) = saved_exit_status;

		PsTerminateSystemThread( STATUS_SUCCESS );
		return o( true );
	}
}