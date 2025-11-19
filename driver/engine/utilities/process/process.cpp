#include "process.hpp"

#include "../../definitions/definitions.hpp"
#include "../oxorany/oxorany_include.h"
#include "../encrypt/encrypt.hpp"
#include "../offsets/offsets.hpp"
#include "../thread/thread.hpp"
#include "../memory/memory.hpp"
#include "../crt/crt.hpp"

namespace utilities::process {
	uint32_t find_process( const char* process ) {
		auto system_process = PsInitialSystemProcess;
		auto currrent_entry = system_process;

		char image_name[ 256 ];


		do {

			crt::memcpy( reinterpret_cast< void* >( &image_name ), reinterpret_cast< void* >( ( uint64_t )currrent_entry + offsets::g_image_file_name ), sizeof( image_name ) );

			if ( crt::strstr( image_name, process ) ) {
				uint32_t active_threads;
				crt::memcpy( reinterpret_cast< void* >( &active_threads ), reinterpret_cast< void* >( ( uint64_t )currrent_entry + offsets::g_active_threads ), sizeof( active_threads ) );

				if ( active_threads ) {
					return *reinterpret_cast< uint32_t* >( ( uint64_t )currrent_entry + offsets::g_unique_process_id );
				}
			}

			auto list = reinterpret_cast< PLIST_ENTRY >( ( uint64_t )( currrent_entry )+offsets::g_active_process_links );
			currrent_entry = reinterpret_cast< PEPROCESS >( ( uint64_t )list->Flink - offsets::g_active_process_links );
		} while ( currrent_entry != system_process );

		return o( 0 );
	}

	bool is_exists( uint32_t pid ) {
		auto system_process = PsInitialSystemProcess;
		auto currrent_entry = system_process;

		char image_name[ 256 ];

		do {
			crt::memcpy( reinterpret_cast< void* >( &image_name ), reinterpret_cast< void* >( ( uint64_t )currrent_entry + offsets::g_image_file_name ), sizeof( image_name ) );

			if ( *reinterpret_cast< uint32_t* >( ( uint64_t )currrent_entry + offsets::g_unique_process_id ) == pid ) {
				return o( true );
			}

			auto list = reinterpret_cast< PLIST_ENTRY >( ( uint64_t )( currrent_entry )+offsets::g_active_process_links );
			currrent_entry = reinterpret_cast< PEPROCESS >( ( uint64_t )list->Flink - offsets::g_active_process_links );
		} while ( currrent_entry != system_process );

		return o( false );
	}

	uint64_t get_module_handle( const wchar_t* name ) {
		if ( !pid || !name )
			return o( 0 );

		PEPROCESS temp_process;
		if ( !NT_SUCCESS( PsLookupProcessByProcessId( HANDLE( pid ), &temp_process ) ) )
			return o( 0 );

		auto peb_address = reinterpret_cast< uint64_t >( PsGetProcessPeb( temp_process ) );
		if ( !peb_address )
			return o( 0 );

		PEB peb{};
		memory::read( directory_table, peb_address, &peb, sizeof( peb ) );

		PEB_LDR_DATA peb_ldr_data{};
		memory::read( directory_table, uint64_t( peb.Ldr ), &peb_ldr_data, sizeof( peb_ldr_data ) );

		LIST_ENTRY* ldr_list_head = ( LIST_ENTRY* )peb_ldr_data.ModuleListLoadOrder.Flink;
		LIST_ENTRY* ldr_current_node = peb_ldr_data.ModuleListLoadOrder.Flink;

		if ( !ldr_list_head || !ldr_current_node )
			return o( 0 );

		do {
			LDR_DATA_TABLE_ENTRY current_entry{ };
			memory::read( directory_table, uint64_t( ldr_current_node ), &current_entry, sizeof( current_entry ) );

			ldr_current_node = current_entry.InLoadOrderModuleList.Flink;

			if ( current_entry.BaseDllName.Length > 0 ) {
				wchar_t name_buffer[ 256 ];
				memory::read( directory_table, uint64_t( current_entry.BaseDllName.Buffer ), &name_buffer, sizeof( name_buffer ) );

				if ( crt::wcscmp( name_buffer, name, true ) ) {
					ObDereferenceObject( temp_process );
					return uint64_t( current_entry.DllBase );
				}
			}
		} while ( ldr_list_head != ldr_current_node );

		ObDereferenceObject( temp_process );
		return o( 0 );
	}

	uint64_t allocate( size_t size ) {
		uint64_t address = o( 0 );

		PEPROCESS temp_process;
		if ( !NT_SUCCESS( PsLookupProcessByProcessId( HANDLE( pid ), &temp_process ) ) )
			return o( false );

		KAPC_STATE state;
		KeAttachProcess( temp_process );

		ZwAllocateVirtualMemory( reinterpret_cast< HANDLE >( o( -1 ) ), reinterpret_cast< void** >( &address ), o( 0 ), &size, o( MEM_COMMIT | MEM_RESERVE ), o( PAGE_EXECUTE_READWRITE ) );
		crt::memset( reinterpret_cast< void* >( address ), o( 0x00 ), size );

		KeDetachProcess( );
		ObDereferenceObject( temp_process );

		return address;
	}

	bool protect( uint64_t address, size_t size, uint32_t protect ) {
		void* base_address = reinterpret_cast< void* >( address );
		DWORD old_protect;

		PEPROCESS temp_process;
		if ( !NT_SUCCESS( PsLookupProcessByProcessId( HANDLE( pid ), &temp_process ) ) )
			return o( false );

		KAPC_STATE state;
		KeStackAttachProcess( temp_process, &state );

		ZwProtectVirtualMemory( reinterpret_cast< HANDLE >( o( -1 ) ), &base_address, &size, ULONG( protect ), &old_protect );

		KeUnstackDetachProcess( &state);
		ObDereferenceObject( temp_process );

		return o( true );
	}

	uint64_t get_import( uint64_t module, const char* function ) {
		if ( !module || !function )
			return o( 0 );

		IMAGE_DOS_HEADER dos_header;
		memory::read( directory_table, module, &dos_header, sizeof( dos_header ) );

		IMAGE_NT_HEADERS nt_header;
		memory::read( directory_table, module + dos_header.e_lfanew, &nt_header, sizeof( nt_header ) );

		IMAGE_IMPORT_DESCRIPTOR descriptor;
		memory::read( directory_table, module + nt_header.OptionalHeader.DataDirectory[ 1 ].VirtualAddress, &descriptor, sizeof( descriptor ) );

		int descriptor_count = o( 0 );
		int thunk_count = 0;

		while ( descriptor.Name ) {
			IMAGE_THUNK_DATA first_thunk;
			memory::read( directory_table, module + descriptor.FirstThunk, &first_thunk, sizeof(first_thunk));

			IMAGE_THUNK_DATA original_first_thunk;
			memory::read( directory_table, module + descriptor.OriginalFirstThunk, &original_first_thunk, sizeof(original_first_thunk));

			thunk_count = o( 0 );

			while (original_first_thunk.u1.AddressOfData) {
				char name[ 256 ];
				memory::read( directory_table, module + original_first_thunk.u1.AddressOfData + o( 0x2 ), &name, sizeof(name));

				auto thunk_offset{ thunk_count * sizeof( uint64_t ) };

				if ( !crt::strcmp( name, function ) ) {
					return module + descriptor.FirstThunk + thunk_offset;
				}

				++thunk_count;

				memory::read( directory_table, module + descriptor.FirstThunk + sizeof( IMAGE_THUNK_DATA ) * thunk_count, &first_thunk, sizeof( first_thunk ) );
				memory::read( directory_table, module + descriptor.OriginalFirstThunk + sizeof( IMAGE_THUNK_DATA ) * thunk_count, &original_first_thunk, sizeof( original_first_thunk ) );
			}

			++descriptor_count;
			memory::read( directory_table, module + nt_header.OptionalHeader.DataDirectory[ 1 ].VirtualAddress + sizeof( IMAGE_IMPORT_DESCRIPTOR ) * descriptor_count, &descriptor, sizeof( descriptor ) );
		}

		return o( 0 );
	}
}