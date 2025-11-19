#include "random.hpp"
#include "../oxorany/oxorany_include.h"

namespace utilities::random {
	unsigned int get_random( ) {
		unsigned int low = *reinterpret_cast< unsigned int* >( o( 0xFFFFF78000000000 ) );
		unsigned int mul = *reinterpret_cast< unsigned int* >( o( 0xFFFFF78000000004 ) );
		uint64_t seed = ( ( uint64_t )( low ) * ( uint64_t )( mul ) ) >> o( 24 );

		return RtlRandomEx( ( unsigned long* )&seed );
	}
}