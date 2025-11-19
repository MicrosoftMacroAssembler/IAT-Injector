#include "physical.hpp"
#include "../oxorany/oxorany_include.h"

namespace utilities::physical {
	uint64_t get_kernel_directory( ) {
		return *reinterpret_cast< uint64_t* >( ( unsigned char* ) PsGetCurrentProcess() + o( 0x28 ) );
	}

	NTSTATUS read_physical_address( PVOID target_address, PVOID lp_buffer, SIZE_T size, SIZE_T* bytes_read ) {
		MM_COPY_ADDRESS copy = { 0 };
		copy.PhysicalAddress.QuadPart = ( LONGLONG )target_address;
		return MmCopyMemory( lp_buffer, copy, size, o( MM_COPY_MEMORY_PHYSICAL ), bytes_read );
	}

	uint64_t translate_linear_address( uint64_t directory_table_base, uint64_t virtual_address ) {
		static const uintptr_t PMASK = ( o( ~0xfull ) << o( 8 ) ) & o( 0xfffffffffull );

		directory_table_base &= o( ~0xf );

		uintptr_t page_offset = virtual_address & ~( o( ~0ul ) << o( 12 ) );
		uintptr_t pte = ( ( virtual_address >> o( 12 ) ) & ( o( 0x1ffll ) ) );
		uintptr_t pt = ( ( virtual_address >> o( 21 ) ) & ( o( 0x1ffll ) ) );
		uintptr_t pd = ( ( virtual_address >> o( 30 ) ) & ( o( 0x1ffll ) ) );
		uintptr_t pdp = ( ( virtual_address >> o( 39 ) ) & ( o( 0x1ffll ) ) );

		size_t readsize = o( 0 );
		uintptr_t pdpe = o( 0 );

		read_physical_address( PVOID( directory_table_base + o( 8 ) * pdp ), &pdpe, sizeof( pdpe ), &readsize );
		if ( ~pdpe & 1 ) {
			return 0;
		}

		uintptr_t pde = 0;
		read_physical_address( PVOID( ( pdpe & PMASK ) + o( 8 ) * pd ), &pde, sizeof( pde ), &readsize );

		if (~pde & o ( 1 )) {
			return o( 0 );
		}

		if (pde & o( 0x80 )) {
			return ( pde & ( o( ~0ull ) << o( 42 ) >> o( 12 ) ) ) + ( virtual_address & ~( o( ~0ull ) << o( 30 ) ) );
		}

		uintptr_t pte_addr = o( 0 );
		read_physical_address( PVOID( ( pde & PMASK ) + o( 8 ) * pt ), &pte_addr, sizeof( pte_addr ), &readsize );

		if ( ~pte_addr & o( 1 ) ) {
			return o( 0 );
		}

		if (pte_addr & o( 0x80 )) {
			return ( pte_addr & PMASK ) + ( virtual_address & ~( o( ~0ull ) << o( 21 ) ) );
		}

		virtual_address = o( 0 );
		read_physical_address( PVOID( ( pte_addr & PMASK ) + o( 8 ) * pte ), &virtual_address, sizeof( virtual_address ), &readsize );
		virtual_address &= PMASK;

		if ( !virtual_address ) {
			return o( 0 );
		}

		return virtual_address + page_offset;
	}

	NTSTATUS write_physical_address( PVOID target_address, PVOID lp_buffer, SIZE_T size, SIZE_T* bytes_written ) {
		if ( !target_address ) {
			return o( STATUS_UNSUCCESSFUL );
		}

		PHYSICAL_ADDRESS addr_to_write = { 0 };
		addr_to_write.QuadPart = LONGLONG( target_address );

		PVOID pmapped_mem = MmMapIoSpaceEx( addr_to_write, size, o( PAGE_READWRITE ) );
		if ( !pmapped_mem ) {
			return o( STATUS_UNSUCCESSFUL );
		}

		__movsb( PBYTE( pmapped_mem ), PBYTE( lp_buffer ), size );

		*bytes_written = size;
		MmUnmapIoSpace( pmapped_mem, size );

		return o( STATUS_SUCCESS );
	}
}