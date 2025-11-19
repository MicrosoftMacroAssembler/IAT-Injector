#include "crt.hpp"

#include "../oxorany/oxorany_include.h"
#define to_lower( chr ) ( ( chr >= o( 'A' ) && chr <= o( 'Z' ) ) ? ( chr + o( 32 ) ) : chr )

namespace utilities::crt {
    void* memcpy( void* dst, const void* src, uint64_t count ) {
        __movsb( PBYTE( dst ), PBYTE( src ), count );
        return dst;
    }

    void* memset( void* src, int val, uint64_t count ) {
        __stosb( ( unsigned char* )( ( unsigned long long )( volatile char* )src ), val, count );
        return src;
    }

    int memcmp( const void* s1, const void* s2, uint64_t n ) {
        if ( n != 0 ) {
            const unsigned char* p1 = ( unsigned char* )s1, * p2 = ( unsigned char* )s2;
            do {
                if ( *p1++ != *p2++ ) return ( *--p1 - *--p2 );
            } while ( --n != 0 );
        }

        return 0;
    }

    char chrlwr( char c ) {
        if ( c >= o( 'A' ) && c <= o( 'Z' ) ) return c - o( 'A' ) + o( 'a' );
        return c;
    }

    int strlen( const char* str ) {
        int chr = o( 0 );
        if ( str ) {
            for ( ; *str != o( 0 ); ++str ) ++chr;
        }
        return chr;
    }

    int strcmp( const char* cs, const char* ct ) {
        if ( cs && ct ) {
            while ( *cs == *ct ) {
                if ( *cs == o( 0 ) && *ct == o( 0 ) ) return o( 0 );
                if ( *cs == o( 0 ) || *ct == o( 0 ) ) break;
                cs++;
                ct++;
            }

            return *cs - *ct;
        }

        return o( -1 );
    }

    int stricmp( const char* cs, const char* ct ) {
        if ( cs && ct ) {
            while ( chrlwr( *cs ) == chrlwr( *ct ) ) {
                if ( *cs == o( 0 ) && *ct == o( 0 ) ) return o( 0 );
                if ( *cs == o( 0 ) || *ct == o( 0 ) ) break;
                cs++;
                ct++;
            }
            return chrlwr( *cs ) - chrlwr( *ct );
        }
        return -1;
    }

    char* strcpy( char* dst, char* src ) {
        char* ret = dst;
        while ( *src ) *dst++ = *src++;
        *dst = o( 0 );
        return ret;
    }

    const char* strstr( char const* str, char const* sub_str ) {
        const char* bp = sub_str;
        const char* back_pos;

        while ( *str != o( 0 ) && str != 0 && sub_str != 0 ) {
            back_pos = str;
            while ( chrlwr( *back_pos++ ) == chrlwr( *sub_str++ ) ) {
                if ( *sub_str == o( 0 ) ) {
                    return ( char* )( back_pos - strlen( bp ) );
                }
            }
            ++str;
            sub_str = bp;
        }

        return 0;
    }

    char* strcat( char* dest, const char* src ) {
        if ( ( dest == 0 ) || ( src == 0 ) )
            return dest;

        while ( *dest != o( 0 ) )
            dest++;

        while ( *src != o( 0 ) ) {
            *dest = *src;
            dest++;
            src++;
        }

        *dest = o( 0 );
        return dest;
    }

    int wcslen( const wchar_t* s ) {
        int cnt = o( 0 );

        if ( !s )
            return o( 0 );
        for ( ; *s != o( 0 ); ++s )
            ++cnt;

        return cnt;
    }

    int wcscmp( const wchar_t* cs, const wchar_t* ct, bool two ) {
        if ( !cs || !ct )
            return false;

        wchar_t c1, c2;
        do {
            c1 = *cs++; c2 = *ct++;
            c1 = to_lower( c1 ); c2 = to_lower( c2 );

            if ( !c1 && ( two ? !c2 : o( 1 ) ) )
                return o( true );

        } while ( c1 == c2 );

        return o( false );
    }
}