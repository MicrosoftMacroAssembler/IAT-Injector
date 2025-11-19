#include "../../../includes/includes.hpp"

namespace utilities::process {
	inline uint64_t directory_table;
	inline uint32_t pid;

	uint32_t find_process( const char* );
	bool is_exists( uint32_t );

	uint64_t get_module_handle( const wchar_t* );

	uint64_t allocate( size_t );
	bool protect( uint64_t, size_t, uint32_t );

	uint64_t get_import( uint64_t, const char* );
}