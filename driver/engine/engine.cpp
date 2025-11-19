#include "engine.hpp"

#include "utilities/oxorany/oxorany_include.h"
#include "utilities/utilities.hpp"

extern "C" {
	inline uint8_t g_key = 0x0d;
	NTKERNELAPI
		PVOID
		PsGetProcessSectionBaseAddress(
			PEPROCESS Process
		);
}

struct InjectData
{
	unsigned int Status;
	unsigned long long EntryPoint;
	unsigned long long A1;
	unsigned int A2;
	unsigned long long A3;
};

extern "C" NTSTATUS NTAPI ExRaiseHardError(
	NTSTATUS ErrorStatus, ULONG NumberOfParameters,
	ULONG UnicodeStringParameterMask, PULONG_PTR Parameters,
	ULONG ValidResponseOptions, PULONG Response);

ULONG KeMessageBox(PCWSTR title, PCWSTR text, ULONG_PTR type)
{
	UNICODE_STRING uTitle = { 0 };
	UNICODE_STRING uText = { 0 };

	RtlInitUnicodeString(&uTitle, title);
	RtlInitUnicodeString(&uText, text);

	ULONG_PTR args[] = { (ULONG_PTR)&uText, (ULONG_PTR)&uTitle, type };
	ULONG response = 0;

	ExRaiseHardError(STATUS_SERVICE_NOTIFICATION, 3, 3, args, 2, &response);
	return response;
}

namespace engine {
	uint32_t pid;

	namespace impl {

		void* get_rva( uint64_t rva, IMAGE_NT_HEADERS* nt_header, void* buffer ) {
			IMAGE_SECTION_HEADER* first_section = IMAGE_FIRST_SECTION( nt_header );

			for ( IMAGE_SECTION_HEADER* section = first_section; section < first_section + nt_header->FileHeader.NumberOfSections; section++ )
				if ( rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize )
					return ( unsigned char* )buffer + section->PointerToRawData + ( rva - section->VirtualAddress );

			return reinterpret_cast< void* >( o( 0 ) );
		}

		bool relocate_image( uint64_t allocated ) {
			IMAGE_DOS_HEADER* dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( dll );
			IMAGE_NT_HEADERS* nt_header = reinterpret_cast< IMAGE_NT_HEADERS* >( dll + dos_header->e_lfanew );

			uint64_t delta_offset = ( uint64_t )allocated - nt_header->OptionalHeader.ImageBase;

			if ( !delta_offset )
				return o( true );
			else if ( !( nt_header->OptionalHeader.DllCharacteristics & o( IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ) ) )
				return o( false );

			reloc_t* reloc_entry = ( reloc_t* )get_rva( nt_header->OptionalHeader.DataDirectory[ o( IMAGE_DIRECTORY_ENTRY_BASERELOC ) ].VirtualAddress, nt_header, dll );
			uint64_t reloc_end = ( uint64_t )reloc_entry + nt_header->OptionalHeader.DataDirectory[ o( IMAGE_DIRECTORY_ENTRY_BASERELOC ) ].Size;

			if ( reloc_entry == nullptr )
				return o( true );

			while ( ( uint64_t )reloc_entry < reloc_end && reloc_entry->size ) {
				DWORD records_count = ( reloc_entry->size - o( 8 ) ) >> o( 1 );

				for ( DWORD i = o( 0 ); i < records_count; i++ ) {
					WORD fix_type = ( reloc_entry->item[ i ].type );
					WORD shift_delta = ( reloc_entry->item[ i ].offset ) % o( 4096 );

					if ( fix_type == o( IMAGE_REL_BASED_ABSOLUTE ) )
						continue;

					if ( fix_type == o( IMAGE_REL_BASED_HIGHLOW ) || fix_type == o( IMAGE_REL_BASED_DIR64 ) ) {
						uint64_t fix_va = ( uint64_t )get_rva( reloc_entry->rva, nt_header, dll );

						if ( !fix_va )
							fix_va = ( uint64_t )dll;

						*( uint64_t* )( fix_va + shift_delta ) += delta_offset;
					}
				}

				reloc_entry = ( reloc_t* )( ( LPBYTE )reloc_entry + reloc_entry->size );
			}

			return o( true );
		}	

		bool thread( ) {


			// initialing kernel offsets

			KeMessageBox(L"Backbone Kernel", L"Hello Earth from kernel", 0);

			if ( !offsets::initialize( ) )
				return false;
			// hiding thread
			
			KeMessageBox(L"Backbone Kernel", L"Hiding this thread!", 0);

			//if ( !thread::hide( ) )
			//	return false;
			// finding process

			// prevent bsod, if process died

			DbgPrintEx(0, 0, "[BackBone] Entry point\n");

			KeMessageBox(L"Backbone Kernel", L"Validating this thread", 0);

			if (!process::is_exists(pid))
			{
				DbgPrintEx(0, 0, "[BackBone] Couldn't find process.\n");
				thread::terminate();
			}

			// attaching to process

			KeMessageBox(L"Backbone Kernel", L"Validating the target process", 0);

			PEPROCESS temp_process;
			if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(pid), &temp_process)))
			{
				DbgPrintEx(0, 0, "[BackBone] Couldn't find process, looking up process ID.\n");
				thread::terminate();
			}

			uint64_t directory_table = pml4::dirbase_from_base_address((void*)PsGetProcessSectionBaseAddress(temp_process));

			KeMessageBox(L"Backbone Kernel", L"Getting Control Register 3 from PLM4", 0);

 			process::directory_table = directory_table;
	 		process::pid = pid;
			
			winapi::sleep(o(5000));

	 		// spoof eac callbacks
 
			ObDereferenceObject( temp_process );

			// injection part

			unsigned char junk[ 0x1000 ];

			for ( int idx = o( 0 ); idx < o( 0x1000 ); ++idx ) {
				junk[ idx ] = random::get_random( ) ^ o( 0x99 );
			}

			IMAGE_DOS_HEADER* dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( dll );
			IMAGE_NT_HEADERS* nt_header = reinterpret_cast< IMAGE_NT_HEADERS* >( dll + dos_header->e_lfanew );

			if ((nt_header->Signature ^ o(0xc0de)) != o(0x858e))
			{
				KeMessageBox(L"Payload Signature", L"Failed to get payload signature", 0);
				thread::terminate();
			}

			winapi::sleep(o(5000));
			IMAGE_OPTIONAL_HEADER* optional_header = reinterpret_cast< IMAGE_OPTIONAL_HEADER* >( &nt_header->OptionalHeader );
			IMAGE_FILE_HEADER* file_header = reinterpret_cast< IMAGE_FILE_HEADER* >( &nt_header->FileHeader );

			// injection shellcode
			unsigned char shellcode[] = {
				0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x39,
				0xFF, 0x90, 0x39, 0xC0, 0x90, 0x48, 0x89, 0x44,
				0x24, 0x20, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x83,
				0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24,
				0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48,
				0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40, 0x08,
				0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0,
				0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44,
				0x24, 0x20, 0x48, 0x8B, 0x48, 0x10, 0xFF, 0x54,
				0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7,
				0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4,
				0x38, 0xC3, 0x48, 0x39, 0xC0, 0x90, 0xCC
			};

			// allocating memory for a dll

			uint64_t allocated = process::allocate( optional_header->SizeOfImage );
			if ( !allocated )
				thread::terminate( );

			// relocating image
			KeMessageBox(L"Backbone Kernel", L"Relocating image", 0);

			if (!relocate_image(allocated))
			{
				KeMessageBox(L"Image Reallocatione", L"Failed to get image reallocation", 0);
				thread::terminate();
			}

			// writing sections

			//memory::write( directory_table, allocated, junk, sizeof( junk ) );
			//memory::write( directory_table, allocated + optional_header->SizeOfImage, junk, sizeof( junk ) );

			auto section_header = IMAGE_FIRST_SECTION( nt_header );
			for ( uint32_t idx = o( 0 ); idx != file_header->NumberOfSections; ++idx, ++section_header ) {
				if ( section_header->SizeOfRawData ) {


					memory::write( directory_table, allocated + section_header->VirtualAddress, dll + section_header->PointerToRawData, section_header->SizeOfRawData );
				}
			}

			// calling entry point

			uint64_t entry_point = optional_header->AddressOfEntryPoint;

			KeMessageBox(L"Backbone Kernel", L"Entry Point", 0);

			DbgPrintEx(0, 0, "[BackBone] Payload entry point -> 0x%llx\n", entry_point);

			//unsigned char shellcode[ ] = { 0x50, 0x52, 0x51, 0x48, 0xB8, 0xDE, 0xC0, 0xFF, 0xAD, 0xDE, 0xFF, 0x00, 0x00, 0x48, 0xBA, 0xDE, 0xC0, 0xFF, 0xAD, 0xDE, 0xFF, 0x00, 0x00, 0x48, 0x89, 0x10, 0x48, 0x33, 0xC0, 0x48, 0xB8, 0xEF, 0xBE, 0xFF, 0x00, 0xED, 0x0D, 0x00, 0x00, 0x48, 0xB9, 0xEF, 0xBE, 0xFF, 0x00, 0xED, 0x0D, 0x00, 0x00, 0xFF, 0xD1, 0x59, 0x5A, 0x58, 0xC3 };

			auto module = process::get_module_handle(e(L"user32.dll"));

			auto import = process::get_import( module , e( "NtUserGetForegroundWindow" ) );
			if ( !import )

			{
				DbgPrintEx(0, 0, "[BackBone] Couldn't find import exploit -> 0x%llx, Module -> 0x%llx\n", import, module);
				thread::terminate();
			}

			KeMessageBox(L"Backbone Kernel", L"Successfully found import entry", 0);

			uint64_t function = o( 0 );
			memory::read( directory_table, import, & function, sizeof( function ) );

			uint64_t allocated_shell = (allocated + (optional_header->SizeOfImage - sizeof(shellcode)));

			DbgPrintEx(0, 0, "[BackBone] Allocated Shellcode -> 0x%llx\n", allocated_shell);

			uintptr_t target_base_address = (uintptr_t)PsGetProcessSectionBaseAddress(temp_process);
			uintptr_t data_address = process::allocate( optional_header->SizeOfImage + sizeof(shellcode) + sizeof(InjectData) );
			memory::write(directory_table, uintptr_t( shellcode + 6 ), &data_address, sizeof(data_address));

			KeMessageBox(L"Backbone Kernel", L"Successfully allocated data", 0);
			DbgPrintEx(0, 0, "[BackBone] Data Address -> 0x%llx\n", data_address);

			InjectData data = {};
			data.Status = 0;
			data.EntryPoint = allocated + entry_point;
			data.A1 = target_base_address;
			data.A2 = 1;
			data.A3 = target_base_address;

			// executing shellcode, using system import hijack
			memory::write(directory_table, data_address, &data, sizeof(data));
			memory::write(directory_table, allocated_shell, &shellcode, sizeof( shellcode ));
			KeMessageBox(L"Backbone Kernel", L"Successfully wrote data and shellcode to allocations", 0);

			//crt::memset( shellcode, 0, sizeof( shellcode ) );

			process::protect( import, sizeof( uint64_t ), o( PAGE_READWRITE ) );
			memory::write( directory_table, import, &allocated_shell, sizeof( allocated_shell ) );
			KeMessageBox(L"Backbone Kernel", L"Successfully swapped import and allocated shellcode", 0);
			winapi::sleep( o( 3000 ) );
			process::protect(import, sizeof(uint64_t), o(PAGE_READONLY));

			// prevent process crash, if address is invalid
			//if ( import != o( 0 ) ) {
			//	process::protect( import, sizeof( uint64_t ), o( PAGE_READONLY ) );
			//	memory::write( directory_table, allocated_shell, junk, sizeof( shellcode ) );
			//	winapi::sleep( o( 1500 ) );
			//}

			KeMessageBox(L"Backbone Kernel", L"Reading data, waiting for injection.", 0);

			while (data.Status != 2)
			{
				memory::read(directory_table, data_address, &data, sizeof(data));
			}

			// injection complete
			// terminating thread and restore values
			DbgPrintEx(0, 0, "[BackBone] Injection Complete!\n");

			thread::terminate( );
		}
	}

	bool initialize( uint32_t a1 ) {
		KeMessageBox(L"Backbone Kernel", L"Hello World from kernel", 0);
		engine::pid = a1;

		HANDLE handle = nullptr;

		OBJECT_ATTRIBUTES object_attribues{ };
		InitializeObjectAttributes( &object_attribues, nullptr, o( OBJ_KERNEL_HANDLE ), nullptr, nullptr );

		// creating system thread
		PsCreateSystemThread( &handle, 0, &object_attribues, nullptr, nullptr, reinterpret_cast< PKSTART_ROUTINE >( &impl::thread ), nullptr );
		return o( true );
	}
}