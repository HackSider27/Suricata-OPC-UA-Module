#ifndef __DETECT_OPCUA_OPCUABUF_H__
#define __DETECT_OPCUA_OPCUABUF_H__

#include "app-layer-opcua.h"

typedef struct DetectOpcua_ {
    uint8_t             type;           /** < Opcua msg type to match */
    uint8_t             function;       /** < Opcua function to match */
    uint8_t             compare;        /** < Opcua compare word to match */
    uint8_t             size;           /** < Opcua packet size to match */
    uint8_t             prev_token;     /** < Opcua previous token to match */
    uint8_t             req;            /** < Opcua request id to match */

} DetectOpcua;

void DetectOPCUAopcuabufRegister(void);

#endif /* __DETECT_OPCUA_OPCUABUF_H__ */