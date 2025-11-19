#include "kernel.hpp"

#include "../oxorany/oxorany_include.h"
#include "../crt/crt.hpp"

#define in_range( x, a, b ) ( x >= a && x <= b ) 
#define get_bits( x ) ( in_range( ( x & ( o( ~0x20 ) ) ), o( 'A' ), o( 'F' ) ) ? ( ( x & ( o( ~0x20 ) ) ) - o( 'A' ) + o( 0xA ) ) : ( in_range( x, o( '0' ), o( '9' ) ) ? x - o( '0' ) : o( 0 ) ) )
#define get_byte( x ) ( get_bits( x[ o( 0 ) ] ) << o( 4 ) | get_bits( x[ o( 1 ) ] ) )

namespace utilities::kernel {
    namespace pattern {
        uint64_t find_pattern( uint64_t base, size_t range, const char* pattern, const char* mask ) {
            const auto check_mask = [ ]( const char* base, const char* pattern, const char* mask ) -> bool {
                for ( ; *mask; ++base, ++pattern, ++mask ) {
                    if ( *mask == o( 'x' ) && *base != *pattern ) {
                        return o( false );
                    }
                }

                return o( true );
                };

            range = range - crt::strlen( mask );

            for ( size_t i = 0; i < range; ++i ) {
                if ( check_mask( ( const char* )base + i, pattern, mask ) ) {
                    return base + i;
                }
            }

            return o( NULL );
        }

        uint64_t find_pattern( uint64_t base, const char* pattern, const char* mask ) {
            const PIMAGE_NT_HEADERS headers = ( PIMAGE_NT_HEADERS )( base + ( ( PIMAGE_DOS_HEADER )base )->e_lfanew );
            const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION( headers );

            for ( size_t i = 0; i < headers->FileHeader.NumberOfSections; i++ ) {
                const PIMAGE_SECTION_HEADER section = &sections[ i ];

                if ( section->Characteristics & o( IMAGE_SCN_MEM_EXECUTE ) ) {
                    const auto match = find_pattern( base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask );

                    if ( match ) {
                        return match;
                    }
                }
            }

            return o( 0 );
        }

        uint64_t find_pattern( uint64_t module_base, const char* pattern ) {
            auto pattern_ = pattern;
            uint64_t first_match = 0;

            if ( !module_base ) {
                return o( 0 );
            }

            const auto nt = reinterpret_cast< IMAGE_NT_HEADERS* >( module_base + reinterpret_cast< IMAGE_DOS_HEADER* >( module_base )->e_lfanew );

            for ( auto current = module_base; current < module_base + nt->OptionalHeader.SizeOfImage; current++ ) {
                if ( !*pattern_ ) {
                    return first_match;
                }

                if ( *( uint8_t* )pattern_ == o( '\?' ) || *( uint8_t* )current == get_byte( pattern_ ) ) {
                    if ( !first_match )
                        first_match = current;

                    if ( !pattern_[ o( 2 ) ] )
                        return first_match;

                    if ( *( uint16_t* )pattern_ == o( '\?\?' ) || *( uint8_t* )pattern_ != o( '\?' ) )
                        pattern_ += o( 3 );

                    else
                        pattern_ += o( 2 );
                }
                else {
                    pattern_ = pattern;
                    first_match = o( 0 );
                }
            }

            return o( 0 );
        }
    }

    void* get_system_information( SYSTEM_INFORMATION_CLASS information_class ) {
        unsigned long size = o( 32 );
        char buffer[ 32 ];

        ZwQuerySystemInformation( information_class, buffer, size, &size );
        void* info = ExAllocatePoolZero( NonPagedPool, size, o( 7265746172 ) );

        if ( !info )
            return o( nullptr );

        if ( !NT_SUCCESS( ZwQuerySystemInformation( information_class, info, size, &size ) ) ) {
            ExFreePool( info );
            return o( nullptr );
        }

        return info;
    }

    uint64_t get_module( const char* module ) {
        const PRTL_PROCESS_MODULES info = ( PRTL_PROCESS_MODULES )get_system_information( SystemModuleInformation );
        if ( !info )
            return o( 0 );

        for ( size_t i = o( 0 ); i < info->NumberOfModules; ++i ) {
            const auto& mod = info->Modules[ i ];

            if ( crt::stricmp( ( char* )mod.FullPathName + mod.OffsetToFileName, module ) == o( 0 ) ) {
                const void* address = mod.ImageBase;
                ExFreePool( info );

                return ( uint64_t )address;
            }
        }

        ExFreePool( info );
        return ( 0 );
    }

    uint64_t get_export( const char* module, const char* function ) {
        uint64_t address = get_module( module );
        if ( !address )
            return o( 0 );

        return reinterpret_cast< uint64_t >( RtlFindExportedRoutineByName( reinterpret_cast< void* >( address ), function ) );
    }

    int get_version( ) {
        RTL_OSVERSIONINFOW ver = { 0 };
        RtlGetVersion( &ver );

        return ver.dwBuildNumber;
    }
}