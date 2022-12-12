#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "app-layer-opcua.h"
#include "detect-opcua-opcuabuf.h"
#include "util-byte.h"

/* Offsets */
#define OPCUA_MIN_FRAME_LEN             24
#define OPCUA_SIZE_OFFSET               4
#define OPCUA_TOKEN_OFFSET              12
#define OPCUA_REQ_OFFSET                20
#define OPCUA_FUNC_OFFSET               26
#define OPCUA_START_TOKEN               0X01

/* For size */
#define LESS                            0X01
#define EQUAL                           0X02
#define GREATER                         0X03

/* OPCUA Function Code. */
#define OPCUA_CREATE_SESSION_REQ        0xcd
#define OPCUA_CREATE_SESSION_RESP       0xd0
#define OPCUA_BROWSE_REQ                0X0f
#define OPCUA_BROWSE_RESP               0X12
#define OPCUA_READ_REQ                  0X77
#define OPCUA_READ_RESP                 0X7a

/* OPCUA msg types */
#define OPCUA_MSG_TYPE                  0x4d
#define OPCUA_HELLO_TYPE                0x48
#define OPCUA_ACK_TYPE                  0x41
#define OPCUA_OPN_TYPE                  0x4f

/**
 * \brief Regex for parsing the opcua msg type string
 */
#define PARSE_REGEX_TYPE "^\\s*\"?\\s*type\\s*([A-z]+)\\s*\"?\\s*$"
static DetectParseRegex type_parse_regex;

/**
 * \brief Regex for parsing the opcua msg size string
 */
#define PARSE_REGEX_SIZE "^\\s*\"?\\s*size\\s*(lt|eq|gt)(\\s+(\\d+))\\s*\"?\\s*$"
static DetectParseRegex size_parse_regex;

/**
 * \brief Regex for parsing the opcua token string
 */
#define PARSE_REGEX_TOKEN "^\\s*\"?\\s*token\\s*\"?\\s*$"
static DetectParseRegex token_parse_regex;

/**
 * \brief Regex for parsing the opcua requestid string
 */
#define PARSE_REGEX_REQ "^\\s*\"?\\s*request\\s*(\\d+)\\s*\"?\\s*$"
static DetectParseRegex req_parse_regex;

/**
 * \brief Regex for parsing the opcua function string
 */
#define PARSE_REGEX_FUNCTION "^\\s*\"?\\s*function\\s*([A-z]+)\\s*\"?\\s*$"
static DetectParseRegex function_parse_regex;


static int g_opcua_opcuabuf_id = 0;

static int DetectOPCUAOPCUASetup(DetectEngineCtx *, Signature *, const char *);

#ifdef UNITTESTS
static void DetectOPCUAOPCUAbufRegisterTests(void);
#endif

/** \internal
 *
 * \brief this function will free memory associated with DetectOpcua
 *
 * \param ptr pointer to DetectOpcua
 */
static void DetectOpcuaFree(DetectEngineCtx *de_ctx, void *ptr) {
    SCEnter();
    DetectOpcua *opcua = (DetectOpcua *) ptr;

    if(opcua) {

        SCFree(opcua);
    }
}

/** \internal
 *
 * \brief This function is used to parse OPCUA parameters in function mode
 *
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the user provided option
 *
 * \retval Pointer to DetectOpcuaData on success or NULL on failure
 */
static DetectOpcua *DetectOpcuaFunctionParse(DetectEngineCtx *de_ctx, const char *str)
{
    SCEnter();
    DetectOpcua *opcua = NULL;

    char    arg[MAX_SUBSTRINGS], *ptr = arg;
    int     ov[MAX_SUBSTRINGS], res, ret;

    SCLogNotice("LOOOOOOOOOOOOOOOOOOL");
    ret = DetectParsePcreExec(&function_parse_regex, str, 0, 0, ov, MAX_SUBSTRINGS);
    SCLogNotice("PcreExec function: %d", ret);
    if (ret < 1)
        goto error;

    res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 1, arg, MAX_SUBSTRINGS);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    /* We have a correct Opcua function option */
    opcua = (DetectOpcua *) SCCalloc(1, sizeof(DetectOpcua));
    if (unlikely(opcua == NULL))

        goto error;


    if (strcmp("createSessionReq", ptr) == 0){
        opcua->function = OPCUA_CREATE_SESSION_REQ;
        opcua->type = OPCUA_MSG_TYPE;
    }
    else if (strcmp("createSessionResp", ptr) == 0){
        opcua->function = OPCUA_CREATE_SESSION_RESP;
        opcua->type = OPCUA_MSG_TYPE;
    }
    else if (strcmp("browseReq", ptr) == 0){
        opcua->function = OPCUA_BROWSE_REQ;
        opcua->type = OPCUA_MSG_TYPE;
    }
    else if (strcmp("browseResp", ptr) == 0){
        opcua->function = OPCUA_BROWSE_RESP;
        opcua->type = OPCUA_MSG_TYPE;
    }
    else if (strcmp("readReq", ptr) == 0){
        opcua->function = OPCUA_READ_REQ;
        opcua->type = OPCUA_MSG_TYPE;
    }
    else if (strcmp("readResp", ptr) == 0){
        opcua->function = OPCUA_READ_RESP;
        opcua->type = OPCUA_MSG_TYPE;
    }
    else
        SCLogError(SC_ERR_INVALID_VALUE, "Invalid value for opcua function: %s", ptr);

    SCLogDebug("will look for opcua function %d", opcua->function);

    SCReturnPtr(opcua, "DetectOpcuaFunction");

error:
    if (opcua != NULL)
        DetectOpcuaFree(de_ctx, opcua);

    SCReturnPtr(NULL, "DetectOpcua");

}

/** \internal
 *
 * \brief This function is used to parse OPCUA parameters in type mode
 *
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the user provided option
 *
 * \retval Pointer to DetectOpcuaData on success or NULL on failure
 */
static DetectOpcua *DetectOpcuaTypeParse(DetectEngineCtx *de_ctx, const char *str)
{
    SCEnter();
    DetectOpcua *opcua = NULL;

    char    arg[MAX_SUBSTRINGS], *ptr = arg;
    int     ov[MAX_SUBSTRINGS], res, ret;

    SCLogNotice("Type? %s", str);

    ret = DetectParsePcreExec(&type_parse_regex, str, 0, 0, ov, MAX_SUBSTRINGS);
    SCLogNotice("PcreExec type: %d", ret);
    if (ret < 1)
        goto error;

    res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 1, arg, MAX_SUBSTRINGS);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    /* We have a correct Opcua type option */
    opcua = (DetectOpcua *) SCCalloc(1, sizeof(DetectOpcua));
    if (unlikely(opcua == NULL)){
        SCLogNotice("Opcua - NULL");
        goto error;
    }

    if (strcmp("HEL", ptr) == 0)
        opcua->type = OPCUA_HELLO_TYPE;
    else if (strcmp("OPN", ptr) == 0)
        opcua->type = OPCUA_OPN_TYPE;
    else if (strcmp("ACK", ptr) == 0)
        opcua->type = OPCUA_ACK_TYPE;
    else if (strcmp("MSG", ptr) == 0)
        opcua->type = OPCUA_MSG_TYPE;
    else {
        SCLogError(SC_ERR_INVALID_VALUE, "Invalid value for opcua msg type: %s", ptr);
        goto error;
    }

    SCLogDebug("will look for opcua type %d", opcua->function);

    SCReturnPtr(opcua, "DetectOpcuaType");

error:
    if (opcua != NULL)
        DetectOpcuaFree(de_ctx, opcua);

    SCReturnPtr(NULL, "DetectOpcua");

}

/** \internal
 *
 * \brief This function is used to parse OPCUA parameters in size mode
 *
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the user provided option
 *
 * \retval Pointer to DetectOpcuaData on success or NULL on failure
 */
static DetectOpcua *DetectOpcuaSizeParse(DetectEngineCtx *de_ctx, const char *str)
{
    SCEnter();
    DetectOpcua *opcua = NULL;

    char    arg[MAX_SUBSTRINGS], *ptr = arg;
    int     ov[MAX_SUBSTRINGS], res, ret;

    SCLogNotice("Size? %s", str);

    ret = DetectParsePcreExec(&size_parse_regex, str, 0, 0, ov, MAX_SUBSTRINGS);
    SCLogNotice("PcreExec size: %d", ret);
    if (ret < 1)
        goto error;

    res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 1, arg, MAX_SUBSTRINGS);
    SCLogNotice("Compare: %s", arg);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    /* We have a correct Opcua option */
    opcua = (DetectOpcua *) SCCalloc(1, sizeof(DetectOpcua));
    if (unlikely(opcua == NULL)){
        SCLogNotice("Opcua - NULL");
        goto error;
    }

    if (strcmp("lt", ptr) == 0)
        opcua->compare = LESS;
    else if (strcmp("eq", ptr) == 0)
        opcua->compare = EQUAL;
    else if (strcmp("gt", ptr) == 0)
        opcua->compare = GREATER;
    else {
        SCLogError(SC_ERR_INVALID_VALUE, "Invalid value: %s", ptr);
        goto error;
    }

    res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 3, arg, MAX_SUBSTRINGS);
    SCLogNotice("Size: %s", arg);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    /* We have a correct Opcua option */
    opcua = (DetectOpcua *) SCCalloc(1, sizeof(DetectOpcua));
    if (unlikely(opcua == NULL)){
        SCLogNotice("Opcua - NULL");
        goto error;
    }

    if (!isdigit((unsigned char)ptr[0]))
        goto error;

    if (StringParseUint8(&opcua->size, 10, 0, (const char *)ptr) < 0) {
        SCLogNotice("Size: %d", opcua->size);
        SCLogError(SC_ERR_INVALID_VALUE, "Invalid value for opcua size: %s", (const char *)ptr);
        goto error;
    }

    SCLogDebug("will look for opcua size %d", opcua->size);

    SCReturnPtr(opcua, "DetectOpcuaType");

error:
    if (opcua != NULL)
        DetectOpcuaFree(de_ctx, opcua);

    SCReturnPtr(NULL, "DetectOpcua");

}

/** \internal
 *
 * \brief This function is used to parse OPCUA parameters in token mode
 *
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the user provided option
 *
 * \retval Pointer to DetectOpcuaData on success or NULL on failure
 */
static DetectOpcua *DetectOpcuaTokenParse(DetectEngineCtx *de_ctx, const char *str)
{
    SCEnter();
    DetectOpcua *opcua = NULL;

    int     ov[MAX_SUBSTRINGS], ret;

    SCLogNotice("Token? %s", str);

    ret = DetectParsePcreExec(&token_parse_regex, str, 0, 0, ov, MAX_SUBSTRINGS);
    SCLogNotice("PcreExec token: %d", ret);
    if (ret < 1)
        goto error;

    /* We have a correct Opcua type option */
    opcua = (DetectOpcua *) SCCalloc(1, sizeof(DetectOpcua));
    if (unlikely(opcua == NULL)){
        SCLogNotice("token Opcua = NULL");
        goto error;
    }

    opcua->prev_token = OPCUA_START_TOKEN;

    SCLogDebug("will look for changing opcua token %d", opcua->prev_token);

    SCReturnPtr(opcua, "DetectOpcuaType");

error:
    if (opcua != NULL)
        DetectOpcuaFree(de_ctx, opcua);

    SCReturnPtr(NULL, "DetectOpcua");

}

/** \internal
 *
 * \brief This function is used to parse OPCUA parameters in request mode
 *
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the user provided option
 *
 * \retval Pointer to DetectOpcuaData on success or NULL on failure
 */
static DetectOpcua *DetectOpcuaReqParse(DetectEngineCtx *de_ctx, const char *str)
{
    SCEnter();
    DetectOpcua *opcua = NULL;

    char    arg[MAX_SUBSTRINGS], *ptr = arg;
    int     ov[MAX_SUBSTRINGS], res, ret;

    SCLogNotice("Request? %s", str);

    ret = DetectParsePcreExec(&req_parse_regex, str, 0, 0, ov, MAX_SUBSTRINGS);
    SCLogNotice("PcreExec req: %d", ret);
    if (ret < 1)
        goto error;

    res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 1, arg, MAX_SUBSTRINGS);
    SCLogNotice("Request id: %s", arg);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    /* We have a correct Opcua option */
    opcua = (DetectOpcua *) SCCalloc(1, sizeof(DetectOpcua));
    if (unlikely(opcua == NULL)){
        SCLogNotice("Opcua - NULL");
        goto error;
    }

    if (!isdigit((unsigned char)ptr[0]))
        goto error;

    if (StringParseUint8(&opcua->req, 10, 0, (const char *)ptr) < 0) {
        SCLogNotice("Request id: %d", opcua->req);
        SCLogError(SC_ERR_INVALID_VALUE, "Invalid value for opcua request id: %s", (const char *)ptr);
        goto error;
    }

    SCLogDebug("will look for opcua request id %d", opcua->req);

    SCReturnPtr(opcua, "DetectOpcuaType");

error:
    if (opcua != NULL)
        DetectOpcuaFree(de_ctx, opcua);

    SCReturnPtr(NULL, "DetectOpcua");

}

/**
 * \brief Checks if the packet sent as the argument, has a valid or invalid
 *        values.
 *
 * \param det_ctx Pointer to the detection engine thread context
 * \param p       Pointer to the Packet currently being matched
 * \param s       Pointer to the Signature, the packet is being currently
 *                matched with
 * \param ctx     Pointer to the keyword_structure(SigMatch) from the above
 *                Signature, the Packet is being currently matched with
 *
 * \retval 0:     no match
 *         1:     match
 */
static int DetectOpcuaMatch(DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    uint8_t* payload = p->payload;
    uint16_t payload_len = p->payload_len;
    DetectOpcua* opcua = (DetectOpcua*)ctx;


    if (payload_len < OPCUA_MIN_FRAME_LEN) {
        SCLogNotice("payload length is too small");
        return 0;
    }

    if (PKT_IS_PSEUDOPKT(p)) {
        SCLogNotice("Pseudopkt detect");
        return 0;
    }

    if (!PKT_IS_TCP(p)) {
        SCLogNotice("Transport protocol does not TCP");
        return 0;
    }



    uint8_t type = *(payload);
    if (opcua->type && opcua->type != type) {
        SCLogNotice("Packet does not pass the filtering by type, actual type = %d, rule = %d", type, opcua->type);
        return 0;
    }

    uint8_t function = *(payload + OPCUA_FUNC_OFFSET);
    if (opcua->function && opcua->function != function){
        SCLogNotice("Packet does not pass the filtering by function, actual function = %d, rule = %d", function, opcua->function);
        return 0;
    }

    if (opcua->size){
            uint8_t size = *(payload + OPCUA_SIZE_OFFSET);
            if (opcua->compare == LESS && opcua->size <= size){
                SCLogNotice("Packet does not pass the filtering by size, actual size = %d, rule = %d", size, opcua->size);
                return 0;
            }
            if (opcua->compare == EQUAL && opcua->size != size){
                SCLogNotice("Packet does not pass the filtering by size, actual size = %d, rule = %d", size, opcua->size);
                return 0;
            }
            if (opcua->compare == GREATER && opcua->size >= size){
                SCLogNotice("Packet does not pass the filtering by size, actual size = %d, rule = %d", size, opcua->size);
                return 0;
            }
    }

    if (opcua->prev_token){
        uint8_t token = *(payload + OPCUA_TOKEN_OFFSET);
        if (opcua->prev_token == token){
        SCLogNotice("Packet does not pass the filtering. Token is the same");
                return 0;
        }
        else
            opcua->prev_token = token;
    }

    uint8_t req = *(payload + OPCUA_REQ_OFFSET);
    if (opcua->req && opcua->req != req){
        SCLogNotice("Packet does not pass the filtering by request id, actual request id = %d, rule = %d", req, opcua->req);
        return 0;
    }

    SCLogNotice("PACKET PASSED the filtering, DETECT");
    return 1;
}

/** \internal
 *
 * \brief this function is used to add the parsed option into the current signature
 *
 * \param de_ctx    Pointer to the Detection Engine Context
 * \param s         Pointer to the Current Signature
 * \param str       Pointer to the user provided option
 *
 * \retval 0:     Success
 *         1:     Failure
 */
static int DetectOPCUAOPCUASetup(DetectEngineCtx *de_ctx, Signature *s,
    const char *str)
{
    /* store list id. Content, pcre, etc will be added to the list at this
     * id. */
    s->init_data->list = g_opcua_opcuabuf_id;

    DetectOpcua    *opcua = NULL;
    SigMatch        *sm = NULL;

    SCLogNotice("LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL");

    /* set the app proto for this signature. This means it will only be
     * evaluated against flows that are ALPROTO_OPCUA */
    if (DetectSignatureSetAppProto(s, ALPROTO_OPCUA) != 0)
        SCReturnInt(-1);

    if ((opcua = DetectOpcuaTypeParse(de_ctx, str)) == NULL) {
        SCLogNotice("type OPCUA NULL");
        if ((opcua = DetectOpcuaSizeParse(de_ctx, str)) == NULL){
            SCLogNotice("size OPCUA NULL");
            if ((opcua = DetectOpcuaTokenParse(de_ctx, str)) == NULL){
                SCLogNotice("token OPCUA NULL");
                if ((opcua = DetectOpcuaReqParse(de_ctx, str)) == NULL){
                    SCLogNotice("request id OPCUA NULL");
                    if ((opcua = DetectOpcuaFunctionParse(de_ctx, str)) == NULL) {
                        SCLogNotice("function OPCUA NULL");
                        SCLogError(SC_ERR_PCRE_MATCH, "invalid opcua option ");
                        goto error;
                    }
                }
            }
        }
    }

    /* Lets get this into a SigMatch and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type    = DETECT_AL_OPCUA_OPCUABUF;
    sm->ctx     = (void *) opcua;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    SCReturnInt(0);

    return 0;

error:
    if (opcua != NULL)
        DetectOpcuaFree(de_ctx, opcua);

    if (sm != NULL)
        SCFree(sm);

    SCReturnInt(-1);
}

/**
 * \brief Registration function for OPCUA keyword
 */
void DetectOPCUAopcuabufRegister(void)
{
    sigmatch_table[DETECT_AL_OPCUA_OPCUABUF].name = "opcua";
    sigmatch_table[DETECT_AL_OPCUA_OPCUABUF].desc = "OPCUA content modififier to match on the opcua buffers";
    sigmatch_table[DETECT_AL_OPCUA_OPCUABUF].Setup = DetectOPCUAOPCUASetup;
    sigmatch_table[DETECT_AL_OPCUA_OPCUABUF].Match = DetectOpcuaMatch;
    sigmatch_table[DETECT_AL_OPCUA_OPCUABUF].Free = DetectOpcuaFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_OPCUA_OPCUABUF].RegisterTests =
        DetectOPCUAOPCUAbufRegisterTests;
#endif

    sigmatch_table[DETECT_AL_OPCUA_OPCUABUF].flags |= SIGMATCH_NOOPT;

    DetectSetupParseRegexes(PARSE_REGEX_FUNCTION, &function_parse_regex);

    DetectSetupParseRegexes(PARSE_REGEX_TYPE, &type_parse_regex);

    DetectSetupParseRegexes(PARSE_REGEX_SIZE, &size_parse_regex);

    DetectSetupParseRegexes(PARSE_REGEX_TOKEN, &token_parse_regex);

    DetectSetupParseRegexes(PARSE_REGEX_REQ, &req_parse_regex);

    SCLogNotice("OPCUA application layer detect registered.");
}


#ifdef UNITTESTS
#include "tests/detect-opcua-opcuabuf.c"
#endif
