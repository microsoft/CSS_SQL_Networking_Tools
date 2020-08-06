// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Data that is stored per Kerberos request/response
    // Kerberos-related enums
    //

    class KerberosData
    {
        public MessageTypes RequestType = MessageTypes.KRB_NONE;
        public MessageTypes ResponseType = MessageTypes.KRB_NONE;
        public bool IsForwardable;
        public int Version;
        public int SourcePort = 0;
        public int errorCode;
        public string ErrorDesc;
        public byte SNameType = 0;
        public string SPNRequested;
        public string TimeStamp=null;
        public uint frameNo;
        public ConversationData convData;
    }

    public enum MessageTypes
    {
        KRB_TGS_REQ =  12,
        KRB_TGS_REP =  13,
        KRB_ERROR   =  30,
        KRB_NONE    = 255      // TODO Have we verified the possible message IDs so we aren't using a valid message number ???
    }

    public enum ErrorCodes
    {
        KDC_ERR_NONE = 0x0,
        KDC_ERR_NAME_EXP = 0x1,
        KDC_ERR_SERVICE_EXP = 0x2,
        KDC_ERR_BAD_PVNO = 0x3,
        KDC_ERR_C_OLD_MAST_KVNO = 0x4,
        KDC_ERR_S_OLD_MAST_KVNO = 0x5,
        KDC_ERR_C_PRINCIPAL_UNKNOWN = 0x6,
        KDC_ERR_S_PRINCIPAL_UNKNOWN = 0x7,
        KDC_ERR_PRINCIPAL_NOT_UNIQUE = 0x8,
        KDC_ERR_NULL_KEY = 0x9,
        KDC_ERR_CANNOT_POSTDATE = 0xA,
        KDC_ERR_NEVER_VALID = 0xB,
        KDC_ERR_POLICY = 0xC,
        KDC_ERR_BADOPTION = 0xD,
        KDC_ERR_ETYPE_NOTSUPP = 0xE,
        KDC_ERR_SUMTYPE_NOSUPP = 0xF,
        KDC_ERR_PADATA_TYPE_NOSUPP = 0x10,
        KDC_ERR_TRTYPE_NO_SUPP = 0x11,
        KDC_ERR_CLIENT_REVOKED = 0x12,
        KDC_ERR_SERVICE_REVOKED = 0x13,
        KDC_ERR_TGT_REVOKED = 0x14,
        KDC_ERR_CLIENT_NOTYET = 0x15,
        KDC_ERR_SERVICE_NOTYET = 0x16,
        KDC_ERR_KEY_EXPIRED = 0x17,
        KDC_ERR_PREAUTH_FAILED = 0x18,
        KDC_ERR_PREAUTH_REQUIRED = 0x19,
        KDC_ERR_SERVER_NOMATCH = 0x1A,
        KDC_ERR_SVC_UNAVAILABLE = 0x1B,
        KRB_AP_ERR_BAD_INTEGRITY = 0x1F,
        KRB_AP_ERR_TKT_EXPIRED = 0x20,
        KRB_AP_ERR_TKT_NYV = 0x21,
        KRB_AP_ERR_REPEAT = 0x22,
        KRB_AP_ERR_NOT_US = 0x23,
        KRB_AP_ERR_BADMATCH = 0x24,
        KRB_AP_ERR_SKEW = 0x25,
        KRB_AP_ERR_BADADDR = 0x26,
        KRB_AP_ERR_BADVERSION = 0x27,
        KRB_AP_ERR_MSG_TYPE = 0x28,
        KRB_AP_ERR_MODIFIED = 0x29,
        KRB_AP_ERR_BADORDER = 0x2A,
        KRB_AP_ERR_BADKEYVER = 0x2C,
        KRB_AP_ERR_NOKEY = 0x2D,
        KRB_AP_ERR_MUT_FAIL = 0x2E,
        KRB_AP_ERR_BADDIRECTION = 0x2F,
        KRB_AP_ERR_METHOD = 0x30,
        KRB_AP_ERR_BADSEQ = 0x31,
        KRB_AP_ERR_INAPP_CKSUM = 0x32,
        KRB_AP_PATH_NOT_ACCEPTED = 0x33,
        KRB_ERR_RESPONSE_TOO_BIG = 0x34,
        KRB_ERR_GENERIC = 0x3C,
        KRB_ERR_FIELD_TOOLONG = 0x3D,
        KDC_ERR_CLIENT_NOT_TRUSTED = 0x3E,
        KDC_ERR_KDC_NOT_TRUSTED = 0x3F,
        KDC_ERR_INVALID_SIG = 0x40,
        KDC_ERR_KEY_TOO_WEAK = 0x41,
        KDC_ERR_CERTIFICATE_MISMATCH = 0x42,
        KRB_AP_ERR_NO_TGT = 0x43,
        KDC_ERR_WRONG_REALM = 0x44,
        KRB_AP_ERR_USER_TO_USER_REQUIRED = 0x45,
        KDC_ERR_CANT_VERIFY_CERTIFICATE = 0x46,
        KDC_ERR_INVALID_CERTIFICATE = 0x47,
        KDC_ERR_REVOKED_CERTIFICATE = 0x48,
        KDC_ERR_REVOCATION_STATUS_UNKNOWN = 0x49,
        KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 0x4a,
        KDC_ERR_CLIENT_NAME_MISMATCH = 0x4b,
        KDC_ERR_KDC_NAME_MISMATCH = 0x4c,
        KDC_ERR_INCONSISTENT_KEY_PURPOSE = 0x4d,
        KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED = 0x4f,
        KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS = 0x5d
    }

}
