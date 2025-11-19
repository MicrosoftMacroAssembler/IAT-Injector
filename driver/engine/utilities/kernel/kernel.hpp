#include "../../../includes/includes.hpp"
#include "../../definitions/definitions.hpp"

namespace utilities::kernel {
	namespace pattern {
		uint64_t find_pattern( uint64_t, size_t, const char*, const char* );
		uint64_t find_pattern( uint64_t, const char*, const char* );
		uint64_t find_pattern( uint64_t, const char* );
	}

	void* get_system_information( SYSTEM_INFORMATION_CLASS );
	uint64_t get_module( const char* );
	uint64_t get_export( const char*, const char* );

	int get_version( );
}