#include "offsets.hpp"

#include "../oxorany/oxorany_include.h"
#include "../kernel/kernel.hpp"

namespace utilities::offsets {
	bool initialize( ) {
		auto system_process = ( PEPROCESS )PsInitialSystemProcess;
		if ( !system_process )
			return o( false );

		auto version = kernel::get_version( );


		if ( version < o( 19000 ) ) {
			g_initial_stack = o( 0x28 );
			g_kernel_stack = o( 0x58 );
			g_create_time = o( 0x600 );
			g_start_address = o( 0x620 );
			g_cid = o( 0x648 );
			g_win32_start_address = o( 0x6a0 );
			g_exit_status = o( 0x710 );
		}
		else if ( version > o( 22000 ) ) {
			g_initial_stack = o( 0x28 );
			g_kernel_stack = o( 0x58 );
			g_create_time = o( 0x480 );
			g_start_address = o( 0x4a0 );
			g_cid = o( 0x4c8 );
			g_win32_start_address = o( 0x520 );
			g_exit_status = o( 0x598 );
		}
		else {
			g_initial_stack = o( 0x28 );
			g_kernel_stack = o( 0x58 );
			g_create_time = o( 0x430 );
			g_start_address = o( 0x450 );
			g_cid = o( 0x478 );
			g_win32_start_address = o( 0x4d0 );
			g_exit_status = o( 0x548 );
		}

		for ( auto i = 0; i < o( 0xFFF ); ++i ) {
			if ( !g_unique_process_id && !g_active_process_links ) {
				if ( *( uint64_t* )( ( uint64_t )system_process + i ) == o( 4 ) &&
					*( uint64_t* )( ( uint64_t )system_process + i + o( 0x8 ) ) > o( 0xFFFF000000000000 ) ) {
					g_unique_process_id = i;
					g_active_process_links = i + o( 0x8 );
				}
			}

			if ( !g_image_file_name && !g_active_threads ) {
				if ( *( uint64_t* )( ( uint64_t )system_process + i ) > o( 0x0000400000000000 ) && *( UINT64* )( ( UINT64 )system_process + i ) < o( 0x0000800000000000 ) &&
					*( uint64_t* )( ( uint64_t )system_process + i + o( 0x48 ) ) > 0 && *( UINT64* )( ( UINT64 )system_process + i + o( 0x48 ) ) < o( 0xFFF )) {
					g_image_file_name = i;
					
					g_active_threads = i + o( 0x48 );
				}
			}

			if ( g_unique_process_id && g_active_process_links && g_image_file_name && g_active_threads )
				return o( true );
		}

		return o( false );
	}
}