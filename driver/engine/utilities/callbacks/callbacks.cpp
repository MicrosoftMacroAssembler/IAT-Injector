#include "callbacks.hpp"

#include "../../definitions/definitions.hpp"
#include "../oxorany/oxorany_include.h"

namespace utilities::callbacks {
    BOOLEAN nmi_callback( pnmi_callback_ctx ctx, BOOLEAN handled ) {
        UNREFERENCED_PARAMETER( handled );
        long previous_state;

        ctx->directory = o( 0 );

        if ( ctx->process == IoGetCurrentProcess( ) )
            ctx->directory = __readcr3( );

        previous_state = KeSetEvent( &ctx->notify_event, o( 0 ), o( FALSE ) );
        return o( TRUE );
    }

    uint64_t get_directory_table( PEPROCESS process ) {
        PEPROCESS execute_process;
        nmi_callback_ctx ctx;
        uint32_t number_of_cores, core_index;
        PKPRCB prcb_address;
        KAFFINITY_EX affinity;
        void* nmi_handle;
        long number_of_attemp;

        ctx.process = process;
        ctx.directory = o( 0 );

        number_of_attemp = o( 0 );
        number_of_cores = KeQueryActiveProcessorCountEx( o( ALL_PROCESSOR_GROUPS ) );

        while ( InterlockedIncrement( &number_of_attemp ) < o( MAXLONG ) ) {
            for ( core_index = 0; core_index < number_of_cores; core_index++ ) {
                prcb_address = KeQueryPrcbAddress( core_index );
                execute_process = NULL;

                if ( prcb_address )
                    execute_process = PsGetThreadProcess( PETHREAD( *reinterpret_cast< uint64_t* >( uint64_t( prcb_address ) + o( 0x8 ) ) ) );

                if ( execute_process == process ) {
                    KeInitializeEvent( &ctx.notify_event, NotificationEvent, o( FALSE ) );
                    nmi_handle = KeRegisterNmiCallback( ( PNMI_CALLBACK )nmi_callback, &ctx );

                    if ( nmi_handle ) {
                        KeInitializeAffinityEx( &affinity );
                        KeAddProcessorAffinityEx( &affinity, core_index );
                        HalSendNMI( &affinity );

                        KeWaitForSingleObject( &ctx.notify_event, Executive, KernelMode, o( FALSE ), ( PLARGE_INTEGER )o( NULL ) );
                        KeDeregisterNmiCallback( nmi_handle );

                        if ( ctx.directory && ( ( ctx.directory >> o( 0x38 ) ) == o( 0x40 ) ) == FALSE ) {
                            return ctx.directory;
                        }
                    }

                    ctx.directory = 0;
                }
            }
        }

        return o( 0 );
    }
}