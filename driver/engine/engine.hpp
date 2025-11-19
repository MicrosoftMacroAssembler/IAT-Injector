#include "../includes/includes.hpp"

namespace engine {
	namespace impl {
		struct reloc_t {
			uint32_t rva;
			uint32_t size;

			struct {
				uint16_t offset : 12;
				uint16_t type : 4;
			} item[1];
		};

		bool thread( );
	}

	bool initialize( uint32_t pid );
}