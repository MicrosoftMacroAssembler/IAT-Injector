#include "includes/includes.hpp"

#include "engine/utilities/oxorany/oxorany_include.h"
#include "engine/utilities/clean/clean.hpp"
#include "engine/engine.hpp"

#pragma comment( linker, "/merge:.pdata=.rdata" )
#pragma comment( linker, "/merge:.rdata=.text" )

NTSTATUS driver_entry( uint32_t pid ) {
    if ( !engine::initialize( pid ) )
        return o( STATUS_UNSUCCESSFUL );

    return o( STATUS_SUCCESS );
}