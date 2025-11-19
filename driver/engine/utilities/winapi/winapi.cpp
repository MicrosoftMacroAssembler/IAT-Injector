#include "winapi.hpp"

#include "../oxorany/oxorany_include.h"

namespace utilities::winapi {
	void sleep( uint32_t ms ) {
		auto interval = __int64( ms * o( -10000i64 ) );
		KeDelayExecutionThread( KernelMode, FALSE, ( PLARGE_INTEGER )&interval );
	}
}