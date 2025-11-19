#include "../../../includes/includes.hpp"

namespace utilities::thread {
	inline void* saved_create_time;
	inline void* saved_start_address;
	inline void* saved_win32_start_address;
	inline void* saved_kernel_stack;
	inline void* saved_cid;
	inline void* saved_exit_status;

	void spoof( void*, void**, void* = 0 );
	bool hide( );
	bool terminate( );
}