#ifndef __APP_LAYER_OPCUA_H__
#define __APP_LAYER_OPCUA_H__

#include "detect-engine-state.h"

#include "queue.h"

#include "rust.h"

/* OPCUA Function Code. */
#define OPCUA_CREATE_SESSION_REQ        0xcd
#define OPCUA_CREATE_SESSION_RESP       0xd0
#define OPCUA_BROWSE_REQ                0X0f
#define OPCUA_BROWSE_RESP               0X12
#define OPCUA_READ_REQ                  0X77
#define OPCUA_READ_RESP                 0X7a

void RegisterOPCUAParsers(void);
void OPCUAParserRegisterTests(void);

typedef struct OPCUATransaction
{
    /** Internal transaction ID. */
    uint64_t tx_id;

    /** Application layer events that occurred
     *  while parsing this transaction. */
    AppLayerDecoderEvents *decoder_events;

    uint8_t *request_buffer;
    uint32_t request_buffer_len;

    uint8_t *response_buffer;
    uint32_t response_buffer_len;

    uint8_t response_done; /*<< Flag to be set when the response is
                            * seen. */

    DetectEngineState *de_state;

    AppLayerTxData tx_data;

    TAILQ_ENTRY(OPCUATransaction) next;

} OPCUATransaction;

typedef struct OPCUAState {

    /** List of OPCUA transactions associated with this
     *  state. */
    TAILQ_HEAD(, OPCUATransaction) tx_list;

    /** A count of the number of transactions created. The
     *  transaction ID for each transaction is allocted
     *  by incrementing this value. */
    uint64_t transaction_max;
} OPCUAState;

#endif /* __APP_LAYER_OPCUA_H__ */
