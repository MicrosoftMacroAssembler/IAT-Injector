#include "../../../includes/includes.hpp"

namespace utilities::offsets {
	inline unsigned int g_unique_process_id = 0;
	inline unsigned int g_active_process_links = 0;
	inline unsigned int g_image_file_name = 0;
	inline unsigned int g_active_threads = 0;

	inline unsigned int g_initial_stack = 0;
	inline unsigned int g_kernel_stack = 0;
	inline unsigned int g_create_time = 0;
	inline unsigned int g_start_address = 0;
	inline unsigned int g_cid = 0;
	inline unsigned int g_win32_start_address = 0;
	inline unsigned int g_exit_status = 0;

	bool initialize( );
}