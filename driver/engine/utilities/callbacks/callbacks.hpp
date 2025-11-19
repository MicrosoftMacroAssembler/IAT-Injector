#include "../../../includes/includes.hpp"

namespace utilities::callbacks {
    typedef struct _nmi_callback_ctx {
        PEPROCESS process;
        uint64_t directory;
        KEVENT notify_event;
    } nmi_callback_ctx, *pnmi_callback_ctx;

    BOOLEAN nmi_callback( pnmi_callback_ctx, BOOLEAN );
    uint64_t get_directory_table( PEPROCESS );
}