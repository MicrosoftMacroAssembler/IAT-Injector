#include "clean.hpp"

#include "../oxorany/oxorany_include.h"
#include "../encrypt/encrypt.hpp"
#include "../kernel/kernel.hpp"
#include "../crt/crt.hpp"

namespace utilities::clean {
	void* resolve_relative_address( void* instruction, unsigned long offset, unsigned long instruction_size ) {
		uint64_t instric = ( uint64_t )instruction;
		long rip_offset = *( long* )( instric + offset );
		void* resolved = ( void* )( instric + instruction_size + rip_offset );

		return resolved;
	}

	bool find_pool_table( uint64_t* ppool_big_table, uint64_t* ppool_big_table_size ) {
		auto ntoskrnl = kernel::get_module( e( "ntoskrnl.exe" ) );
		if ( !ntoskrnl )
			return false;

		IMAGE_DOS_HEADER* dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( ntoskrnl );
		IMAGE_NT_HEADERS* nt_header = reinterpret_cast< IMAGE_NT_HEADERS* >( ntoskrnl + dos_header->e_lfanew );

		if ( ( dos_header->e_magic ^ o( 0xc0de ) ) != o( 0x9a93 ) )
			return false;

		IMAGE_OPTIONAL_HEADER* optional_header = reinterpret_cast< IMAGE_OPTIONAL_HEADER* >( &nt_header->OptionalHeader );

		void* ex_protect_pool_ex_ptr = ( void* )kernel::pattern::find_pattern( ( uint64_t )ntoskrnl, optional_header->SizeOfImage, e( "\xE8\x00\x00\x00\x00\x83\x67\x0C\x00" ), e( "x????xxxx" ) );
		if ( !ex_protect_pool_ex_ptr )
			return false;

		void* ex_protect_pool_ex = resolve_relative_address( ex_protect_pool_ex_ptr, o( 1 ), o( 5 ) );
		if ( !ex_protect_pool_ex )
			return false;

		void* pool_big_table_ptr = ( void* )( ( uint64_t )ex_protect_pool_ex + o( 0x95 ) );
		*ppool_big_table = ( uint64_t )resolve_relative_address( pool_big_table_ptr, o( 3 ), o( 7 ) );

		void* pool_big_table_size_ptr = ( void* )( ( uint64_t )ex_protect_pool_ex + o( 0x8E ) );
		*ppool_big_table_size = ( uint64_t )resolve_relative_address( pool_big_table_size_ptr, o( 3 ), o( 7 ) );

		return true;
	}

	bool clean_from_big_pools( uint64_t pool ) {
		uint64_t ppool_big_table = o( 0 );
		uint64_t ppool_big_table_size = o( 0 );

		if ( find_pool_table( &ppool_big_table, &ppool_big_table_size ) ) {
			PPOOL_TRACKER_BIG_PAGES pool_big_table = reinterpret_cast< PPOOL_TRACKER_BIG_PAGES >( o( 0 ) );
			crt::memcpy( &pool_big_table, ( void* )ppool_big_table, o( 8 ) );

			SIZE_T pool_big_table_size = 0;
			crt::memcpy( &pool_big_table_size, ( void* )ppool_big_table_size, o( 8 ) );

			for ( int i = 0; i < pool_big_table_size; i++ ) {
				if ( pool_big_table[ i ].Va == pool || pool_big_table[ i ].Va == ( pool + o( 0x1 ) ) ) {
					pool_big_table[ i ].Va = o( 0x1 );
					pool_big_table[ i ].NumberOfBytes = o( 0x0 );

					return o( true );
				}
			}

			return o( false );
		}

		return o( false );
	}
	
	bool null_page_frame_numbers( PMDL mdl ) {
		PPFN_NUMBER mdl_pages = MmGetMdlPfnArray( mdl );
		if ( !mdl_pages ) { return false; }

		ULONG mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES( MmGetMdlVirtualAddress( mdl ), MmGetMdlByteCount( mdl ) );

		ULONG null_pfn = 0x0;

		MM_COPY_ADDRESS source_address = { 0 };
		source_address.VirtualAddress = &null_pfn;

		auto mm_copy = MmCopyMemory;

		for ( ULONG i = 0; i < mdl_page_count; i++ ) {
			size_t bytes = 0;
			mm_copy( &mdl_pages[ i ], source_address, sizeof( ULONG ), MM_COPY_MEMORY_VIRTUAL, &bytes );
		}

		return true;
	}

	bool prevent_callback( ) {
		struct notify_entry_t {
			EX_RUNDOWN_REF lock;
			void* pad;
			void* callback;
			LIST_ENTRY list;
		};

		auto ntoskrnl = kernel::get_module( e( "ntoskrnl.exe" ) );
		if ( !ntoskrnl )
			return false;

		auto easy_anti_cheat = kernel::get_module( e( "EasyAntiCheat_EOS.sys" ) );
		if ( !easy_anti_cheat )
			return false;

		IMAGE_DOS_HEADER* dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( easy_anti_cheat );
		IMAGE_NT_HEADERS* nt_header = reinterpret_cast< IMAGE_NT_HEADERS* >( easy_anti_cheat + dos_header->e_lfanew );

		if ( nt_header->Signature != 0x4550 )
			return false;

		IMAGE_OPTIONAL_HEADER* optional_header = reinterpret_cast< IMAGE_OPTIONAL_HEADER* >( &nt_header->OptionalHeader );

		auto head = reinterpret_cast< LIST_ENTRY* >( ntoskrnl + 0xCEC720 );
		auto current = head;

		do {
			const notify_entry_t* entry = CONTAINING_RECORD( current, notify_entry_t, list );

			if ( entry->callback >= reinterpret_cast< void* >( easy_anti_cheat ) && entry->callback <= reinterpret_cast< void* >( easy_anti_cheat + optional_header->SizeOfImage ) ) {
				current->Blink->Flink = current->Flink;
				current->Flink->Blink = current->Blink;

				break;
			}
		} while ( current->Flink != head && ( current = current->Flink ) );

		return true;
	}
}