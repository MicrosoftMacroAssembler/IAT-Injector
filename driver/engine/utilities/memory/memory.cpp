#include "memory.hpp"

#include "../oxorany/oxorany_include.h"
#include "../physical/physical.hpp"
#include "../encrypt/encrypt.hpp"

namespace utilities::memory {
	bool write( uint64_t directory_table, uint64_t virtual_address, void* buffer, size_t size ) {
		size_t current_offset = o( 0 );
		size_t total_size = size;

		NTSTATUS status = o( STATUS_UNSUCCESSFUL );

		while ( total_size ) {
			int64_t physical_address = physical::translate_linear_address( directory_table, virtual_address + current_offset );
			if ( !physical_address ) {
				return o( false );
			}

			SIZE_T bytes_written = 0;
			status = physical::write_physical_address( PVOID( physical_address ), reinterpret_cast< void* >( ( uint64_t )buffer + current_offset ), min( o( PAGE_SIZE ) - ( physical_address & o( 0xFFF ) ), total_size ), &bytes_written );

			total_size -= bytes_written;
			current_offset += bytes_written;

			if ( status != o( STATUS_SUCCESS ) || bytes_written == o( 0 ) ) {
				break;
			}
		}

		return o( true );
	}

	bool read( uint64_t directory_table, uint64_t virtual_address, void* buffer, size_t size ) {
		size_t current_offset = o( 0 );
		size_t total_size = size;

		NTSTATUS status = o( STATUS_UNSUCCESSFUL );

		while ( total_size ) {
			int64_t physical_address = physical::translate_linear_address( directory_table, virtual_address + current_offset );
			if ( !physical_address ) {
				return o( false );
			}

			size_t bytes_read = 0;
			status = physical::read_physical_address( PVOID( physical_address ), reinterpret_cast< void* >( ( uint64_t )buffer + current_offset ), min( o( PAGE_SIZE ) - ( physical_address & o( 0xFFF ) ), total_size ), &bytes_read );

			total_size -= bytes_read;
			current_offset += bytes_read;

			if ( status != o( STATUS_SUCCESS ) || bytes_read == o( 0 ) ) {
				break;
			}
		}

		return o( true );
	}


}