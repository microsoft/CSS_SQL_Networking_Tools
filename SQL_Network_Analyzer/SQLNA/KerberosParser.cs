// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;
using System.IO;


namespace SQLNA
{
    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Parse kerberos TGS request / response
    //
    // http://www.rfc-editor.org/rfc/rfc4120.txt
    // https://technet.microsoft.com/en-us/library/bb463166.aspx
    //

    class KerberosParser
    {



        static string GetErrorDesc(ErrorCodes ErrorCode)
        {
            string ErrorDesciption = "";
            Dictionary<ErrorCodes, string> ErrorMessages = new Dictionary<ErrorCodes, string>
            {
                {ErrorCodes.KDC_ERR_NONE,	"No error(KDC_ERR_NONE)"},
                {ErrorCodes.KDC_ERR_NAME_EXP,	"Client's entry in KDC database has expired(KDC_ERR_NAME_EXP)"},
                {ErrorCodes.KDC_ERR_SERVICE_EXP,	"Server's entry in KDC database has expired(KDC_ERR_SERVICE_EXP)"},
                {ErrorCodes.KDC_ERR_BAD_PVNO,	"Requested Kerberos version number not supported(KDC_ERR_BAD_PVNO)"},
                {ErrorCodes.KDC_ERR_C_OLD_MAST_KVNO,	"Client's key encrypted in old master key(KDC_ERR_C_OLD_MAST_KVNO)"},
                {ErrorCodes.KDC_ERR_S_OLD_MAST_KVNO,	"Server's key encrypted in old master key(KDC_ERR_S_OLD_MAST_KVNO)"},
                {ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN,	"Client not found in Kerberos database(KDC_ERR_C_PRINCIPAL_UNKNOWN)"},
                {ErrorCodes.KDC_ERR_S_PRINCIPAL_UNKNOWN,	"Server not found in Kerberos database(KDC_ERR_S_PRINCIPAL_UNKNOWN)"},
                {ErrorCodes.KDC_ERR_PRINCIPAL_NOT_UNIQUE,	"Multiple principal entries in KDC database(KDC_ERR_PRINCIPAL_NOT_UNIQUE)"},
                {ErrorCodes.KDC_ERR_NULL_KEY,	"The client or server has a null key (master key)(KDC_ERR_NULL_KEY)"},
                {ErrorCodes.KDC_ERR_CANNOT_POSTDATE,	"Ticket (TGT) not eligible for postdating(KDC_ERR_CANNOT_POSTDATE)"},
                {ErrorCodes.KDC_ERR_NEVER_VALID,	"Requested start time is later than end time(KDC_ERR_NEVER_VALID)"},
                {ErrorCodes.KDC_ERR_POLICY,	"Requested start time is later than end time(KDC_ERR_POLICY)"},
                {ErrorCodes.KDC_ERR_BADOPTION,	"KDC cannot accommodate requested option(KDC_ERR_BADOPTION)"},
                {ErrorCodes.KDC_ERR_ETYPE_NOTSUPP,	"KDC has no support for encryption type(KDC_ERR_ETYPE_NOTSUPP)"},
                {ErrorCodes.KDC_ERR_SUMTYPE_NOSUPP,	"KDC has no support for checksum type(KDC_ERR_SUMTYPE_NOSUPP)"},
                {ErrorCodes.KDC_ERR_PADATA_TYPE_NOSUPP,	"KDC has no support for PADATA type (pre-authentication data)(KDC_ERR_PADATA_TYPE_NOSUPP)"},
                {ErrorCodes.KDC_ERR_TRTYPE_NO_SUPP,	"KDC has no support for transited type(KDC_ERR_TRTYPE_NO_SUPP)"},
                {ErrorCodes.KDC_ERR_CLIENT_REVOKED,	"Client’s credentials have been revoked(KDC_ERR_CLIENT_REVOKED)"},
                {ErrorCodes.KDC_ERR_SERVICE_REVOKED,	"Credentials for server have been revoked(KDC_ERR_SERVICE_REVOKED)"},
                {ErrorCodes.KDC_ERR_TGT_REVOKED,	"TGT has been revoked(KDC_ERR_TGT_REVOKED)"},
                {ErrorCodes.KDC_ERR_CLIENT_NOTYET,	"Client not yet valid—try again later(KDC_ERR_CLIENT_NOTYET)"},
                {ErrorCodes.KDC_ERR_SERVICE_NOTYET,	"Server not yet valid—try again later(KDC_ERR_SERVICE_NOTYET)"},
                {ErrorCodes.KDC_ERR_KEY_EXPIRED,	"Password has expired—change password to reset(KDC_ERR_KEY_EXPIRED)"},
                {ErrorCodes.KDC_ERR_PREAUTH_FAILED,	"Pre-authentication information was invalid(KDC_ERR_PREAUTH_FAILED)"},
                {ErrorCodes.KDC_ERR_PREAUTH_REQUIRED,	"Additional preauthentication required(KDC_ERR_PREAUTH_REQUIRED)"},
                {ErrorCodes.KDC_ERR_SERVER_NOMATCH,	"KDC does not know about the requested server(KDC_ERR_SERVER_NOMATCH)"},
                {ErrorCodes.KDC_ERR_SVC_UNAVAILABLE,	"KDC is unavailable(KDC_ERR_SVC_UNAVAILABLE)"},
                {ErrorCodes.KRB_AP_ERR_BAD_INTEGRITY,	"Integrity check on decrypted field failed(KRB_AP_ERR_BAD_INTEGRITY)"},
                {ErrorCodes.KRB_AP_ERR_TKT_EXPIRED,	"The ticket has expired(KRB_AP_ERR_TKT_EXPIRED)"},
                {ErrorCodes.KRB_AP_ERR_TKT_NYV,	"The ticket is not yet valid(KRB_AP_ERR_TKT_NYV)"},
                {ErrorCodes.KRB_AP_ERR_REPEAT,	"The request is a replay(KRB_AP_ERR_REPEAT)"},
                {ErrorCodes.KRB_AP_ERR_NOT_US,	"The ticket is not for us(KRB_AP_ERR_NOT_US)"},
                {ErrorCodes.KRB_AP_ERR_BADMATCH,	"The ticket and authenticator do not match(KRB_AP_ERR_BADMATCH)"},
                {ErrorCodes.KRB_AP_ERR_SKEW,	"The clock skew is too great(KRB_AP_ERR_SKEW)"},
                {ErrorCodes.KRB_AP_ERR_BADADDR,	"Network address in network layer header doesn't match address inside ticket(KRB_AP_ERR_BADADDR)"},
                {ErrorCodes.KRB_AP_ERR_BADVERSION,	"Protocol version numbers don't match (PVNO)(KRB_AP_ERR_BADVERSION)"},
                {ErrorCodes.KRB_AP_ERR_MSG_TYPE,	"Message type is unsupported(KRB_AP_ERR_MSG_TYPE)"},
                {ErrorCodes.KRB_AP_ERR_MODIFIED,	"Message stream modified and checksum didn't match(KRB_AP_ERR_MODIFIED)"},
                {ErrorCodes.KRB_AP_ERR_BADORDER,	"Message out of order (possible tampering)(KRB_AP_ERR_BADORDER)"},
                {ErrorCodes.KRB_AP_ERR_BADKEYVER,	"Specified version of key is not available(KRB_AP_ERR_BADKEYVER)"},
                {ErrorCodes.KRB_AP_ERR_NOKEY,	"Service key not available(KRB_AP_ERR_NOKEY)"},
                {ErrorCodes.KRB_AP_ERR_MUT_FAIL,	"Mutual authentication failed(KRB_AP_ERR_MUT_FAIL)"},
                {ErrorCodes.KRB_AP_ERR_BADDIRECTION,	"Incorrect message direction(KRB_AP_ERR_BADDIRECTION)"},
                {ErrorCodes.KRB_AP_ERR_METHOD,	"Alternative authentication method required(KRB_AP_ERR_METHOD)"},
                {ErrorCodes.KRB_AP_ERR_BADSEQ,	"Incorrect sequence number in message(KRB_AP_ERR_BADSEQ)"},
                {ErrorCodes.KRB_AP_ERR_INAPP_CKSUM,	"Inappropriate type of checksum in message (checksum may be unsupported)(KRB_AP_ERR_INAPP_CKSUM)"},
                {ErrorCodes.KRB_AP_PATH_NOT_ACCEPTED,	"Desired path is unreachable(KRB_AP_PATH_NOT_ACCEPTED)"},
                {ErrorCodes.KRB_ERR_RESPONSE_TOO_BIG,	"Too much data(KRB_ERR_RESPONSE_TOO_BIG)"},
                {ErrorCodes.KRB_ERR_GENERIC,	"Generic error; the description is in the e-data field(KRB_ERR_GENERIC)"},
                {ErrorCodes.KRB_ERR_FIELD_TOOLONG,	"Field is too long for this implementation(KRB_ERR_FIELD_TOOLONG)"},
                {ErrorCodes.KDC_ERR_CLIENT_NOT_TRUSTED,	"The client trust failed or is not implemented(KDC_ERR_CLIENT_NOT_TRUSTED)"},
                {ErrorCodes.KDC_ERR_KDC_NOT_TRUSTED,	"The KDC server trust failed or could not be verified(KDC_ERR_KDC_NOT_TRUSTED)"},
                {ErrorCodes.KDC_ERR_INVALID_SIG,	"The signature is invalid(KDC_ERR_INVALID_SIG)"},
                {ErrorCodes.KDC_ERR_KEY_TOO_WEAK,	"A higher encryption level is needed(KDC_ERR_KEY_TOO_WEAK)"},
                {ErrorCodes.KRB_AP_ERR_USER_TO_USER_REQUIRED,	"User-to-user authorization is required(KRB_AP_ERR_USER_TO_USER_REQUIRED)"},
                {ErrorCodes.KRB_AP_ERR_NO_TGT,	"No TGT was presented or available(KRB_AP_ERR_NO_TGT)"},
                {ErrorCodes.KDC_ERR_WRONG_REALM,	"Incorrect domain or principal(KDC_ERR_WRONG_REALM)"},
                {ErrorCodes.KDC_ERR_CANT_VERIFY_CERTIFICATE, "Client cert not verifaible to trusted root cert(KDC_ERR_CANT_VERIFY_CERTIFICATE)"},
                {ErrorCodes.KDC_ERR_INVALID_CERTIFICATE, "client cert had invalid signature(KDC_ERR_INVALID_CERTIFICATE) "},
                {ErrorCodes.KDC_ERR_REVOKED_CERTIFICATE, "client cert was revoked(KDC_ERR_REVOKED_CERTIFICATE)"},
                {ErrorCodes.KDC_ERR_REVOCATION_STATUS_UNKNOWN, "client cert revoked, reason unknown(KDC_ERR_REVOCATION_STATUS_UNKNOWN)"},
                {ErrorCodes.KDC_ERR_REVOCATION_STATUS_UNAVAILABLE, "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE(KDC_ERR_REVOCATION_STATUS_UNAVAILABLE)"}, //DESC unknown
                {ErrorCodes.KDC_ERR_CLIENT_NAME_MISMATCH, "mismatch between client cert and principal name(KDC_ERR_CLIENT_NAME_MISMATCH)"},
                {ErrorCodes.KDC_ERR_KDC_NAME_MISMATCH, "KDC_ERR_KDC_NAME_MISMATCH(KDC_ERR_KDC_NAME_MISMATCH)"}, //DESC unknwon
                {ErrorCodes.KDC_ERR_INCONSISTENT_KEY_PURPOSE, "bad extended key use(KDC_ERR_INCONSISTENT_KEY_PURPOSE)"},
                {ErrorCodes.KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED, "missing paChecksum in PA-PK-AS-REQ(KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED)"},
                {ErrorCodes.KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS, "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS(KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS)"}
               };


            if (!ErrorMessages.TryGetValue((ErrorCodes)ErrorCode, out ErrorDesciption))
                return "Unknown Error";
            else
                return ErrorDesciption;
                
        }

        public static void ReassembleFrames(ConversationData c)
        {

            string Sender = "";
            string SenderofCurrentFrame = "";
            MemoryStream PayLoad = new MemoryStream(10240); //10 KB 

            try
            {
                for (int Index = 0; Index < c.frames.Count; Index++)
                {
                    FrameData fd = (FrameData)c.frames[Index];
                    if ((fd.flags == (int)TCPFlag.ACK) && (fd.payloadLength >= 1))
                    {
                        Sender = fd.isFromClient ? fd.conversation.sourceIP.ToString() : fd.conversation.destIP.ToString();

                        for (; ((Index < c.frames.Count)); Index++)
                        {
                            FrameData CurrentFrame = ((FrameData)c.frames[Index]);
                            SenderofCurrentFrame = CurrentFrame.isFromClient ? CurrentFrame.conversation.sourceIP.ToString() : CurrentFrame.conversation.destIP.ToString();

                            if (SenderofCurrentFrame == Sender)
                            {
                              
                                    if ((CurrentFrame.payloadLength != 0) && (CurrentFrame.payload != null))
                                        PayLoad.Write(CurrentFrame.payload, 0, CurrentFrame.payloadLength);

                            }

                            if ((CurrentFrame.flags == (int)(TCPFlag.ACK | TCPFlag.PUSH)) && (SenderofCurrentFrame == Sender))
                            {
                                CurrentFrame.reassembledPayLoad = PayLoad.ToArray();
                                break;
                            }
                        }
                    }
                }
                PayLoad.Close();
            }
            catch (Exception)
            {
                throw;
            }

        }
        static KerberosData ParseErrorResponseUDP(TDSReader ByteReader)
        {
            int TagID = 10, TagLen = 0, DataLen = 0;
         
            KerberosData KerbData = new KerberosData();

            ReadAsnLen(ByteReader); //Skip over 4 bytes 'ApplicationTag'
            ReadAsnLen(ByteReader); //Skip over 4 bytes 'SequenceHeader'
            do
            {
                TagID = ByteReader.ReadByte();
                TagLen = ReadAsnLen(ByteReader, false);
                switch (TagID & 0x1F)
                {
                    case 0:
                    case 1:
                    case 4:
                    case 5:
                    case 9:
                        break;
                    case 6:
                        {
                            DataLen = ReadAsnLen(ByteReader, false);
                            if (DataLen == 1)
                            {
                               KerbData.errorCode = ByteReader.ReadByte();
                               KerbData.ErrorDesc =  GetErrorDesc((ErrorCodes)KerbData.errorCode);

                            }

                            return KerbData;
                        }

                } //Switch
            }
            while ((TagID & (int)0x1F) <= 9);


            return KerbData;
        }


        static Int32 ReadAsnLen(TDSReader ByteReader, bool IsReadFirstByte = true)
        {

            if (IsReadFirstByte)
                ByteReader.ReadByte();

            int Len = ByteReader.ReadByte();

            if ((Len & (int)0x80) == (int)0x80)
            {
                switch (Len & 0x7F)
                {
                    case 1:
                        {
                            Len = ByteReader.ReadByte();
                            break;
                        }
                    case 2:
                        {
                            Len = ByteReader.ReadBigEndianUInt16();
                            break;
                        }
                    case 3:
                        {
                            Len = (int)ByteReader.ReadUInt32();
                            break;
                        }
                    default:
                        {
                            //throw new Exception("Unknown tag (" + Len + ") in kerberos packet.");
                            break;
                        }
                            

                }
            }
            return Len;
        }

        static  MessageTypes GetMessageType(KerberosData KerbData, TDSReader ByteReader)
        {
            int Len = ReadAsnLen(ByteReader);

            int MsgType = ByteReader.ReadByte();
            if (Len == 1)
            {
               
                if (MsgType == (int)MessageTypes.KRB_TGS_REQ)
                {
                    KerbData.RequestType = MessageTypes.KRB_TGS_REQ;
                }
                else if (MsgType == (int)MessageTypes.KRB_ERROR)
                {
                    KerbData.ResponseType = MessageTypes.KRB_ERROR;
                }
                else if (MsgType == (int)MessageTypes.KRB_TGS_REP)
                {
                    KerbData.ResponseType = MessageTypes.KRB_TGS_REP;
                }

                return (MessageTypes)MsgType;
            }
            else // bug in the code if we get here ...
            {
                throw new Exception("Invalid KERB Request length: " + Len);
            }
        }

        static void ParseNonErrorResponseTCP(KerberosData KerbData, TDSReader ByteReader)
        {
            //Tag4-TagC
            //int TagID = 0, TagLen = 0;

            //do
            //{
            //    TagID = ByteReader.ReadByte();
            //    TagLen = ReadAsnLen(ByteReader, false);
            //    TagID = (TagID & (int)0x1F);
               

            //    switch (TagID)
            //    {
            //        case 0:
            //        case 1:
            //        case 2:
            //        case 3:
            //        case 4:
            //        case 5:
            //        case 6:
            //            {
            //                ByteReader.ReadBytes(TagLen); // Skip 'Crealm', 'Cname', 'Ticket' and 'EncPart'
            //                break;
            //            }
            //        default:
            //            {
            //                throw new Exception("Unexpected Tag " + TagID + " found in KERB TCP error response" );
            //            }
            //    }

            //}
            //while (TagID < 6); //total 6 tags expected 
        }


        static void ParseNonErrorResponseUDP(KerberosData KerbData, TDSReader ByteReader)
        {
            /*
            int TagID = 0, TagLen = 0;
            return;

            do
            {
                TagID = ByteReader.ReadByte();
                TagLen = ReadAsnLen(ByteReader, false);

                TagID = (TagID & (int)0x1F);
                switch (TagID)
                {

                    case 3:
                    case 4:
                        {
                            ByteReader.ReadBytes(TagLen); // Skip 'Crealm', 'Cname', 
                            break;
                        }
                    case 5:
                        {
                            //Skip Tag5->Ticket->ApplicationTag
                            ReadAsnLen(ByteReader);

                            //Skip Tag5->Ticket->SequenceHeader
                            ReadAsnLen(ByteReader);

                            int InnerTagID = -1;
                            int InnerTagLen = 0;

                            do
                            {
                                InnerTagID = ByteReader.ReadByte() & (int)0x1F;
                                InnerTagLen = ReadAsnLen(ByteReader, false);


                                switch (InnerTagID)
                                {

                                    case 0: //Tag0->TktVno                    
                                    case 1: //Skip Tag1->Realm
                                        {
                                            ByteReader.ReadBytes(InnerTagLen);
                                            break;
                                        }
                                    case 2: //Ticket->Sname
                                        {
                                            //int Length = ReadAsnLen(ByteReader); //Skip sequenceheader  of sname.
                                            //ByteReader.ReadByte();


                                            //Skip Tag5->Ticket->Sname->SequenceHeader
                                            ReadAsnLen(ByteReader);
                                            int IInnerTagID = -1;
                                            int IInnerTagLen = 0;

                                            do
                                            {
                                                IInnerTagID = ByteReader.ReadByte() & (int)0x1F;
                                                IInnerTagLen = ReadAsnLen(ByteReader, false);
                                                switch (IInnerTagID)
                                                {
                                                    case 0:
                                                        {
                                                            ByteReader.ReadBytes(IInnerTagLen);
                                                            break;
                                                        }
                                                    case 1:
                                                        {
                                                            ByteReader.ReadByte();
                                                            ByteReader.ReadByte();

                                                            ByteReader.ReadByte();

                                                            int Length = ByteReader.ReadByte();
                                                            String Class = ByteReader.ReadAnsiString(Length);

                                                            ByteReader.ReadByte();
                                                            Length = ByteReader.ReadByte();
                                                            KerbData.SPNRequested = Class + "/" + ByteReader.ReadAnsiString(Length);
                                                            break;
                                                        }

                                                }
                                            } while (IInnerTagID < 1);
                                            //KerbData.SPNRequested = ByteReader.ReadAnsiString(InnerTagLen);
                                            break;
                                        }
                                }
                            }
                            while (InnerTagID < 2); // Read until Sname

                            break;
                        }
                    default:
                        {
                            throw new Exception("Unexpected Tag " + TagID + " found in  KERB TCP response");
                        }
                }

            }
            while (TagID < 5); 
            */
        }

        static void ParseErrorResponseTCP(KerberosData KerbData, TDSReader ByteReader)
        {
            
            //Tag4-TagC
            int TagID = 0, TagLen = 0;
            do
            {
                TagID = ByteReader.ReadByte();
                TagLen = ReadAsnLen(ByteReader, false);

                TagID = (TagID & (int)0x1F);
                switch (TagID)
                {
                    case 4:
                    case 5:
                    case 9:
                    case 10:
                    case 12:
                        {
                            ByteReader.ReadBytes(TagLen); // Skip 'STime', 'SuSec', 'Realm'
                            break;
                        }
                    case 6:
                        {
                            ReadAsnLen(ByteReader);
                            KerbData.errorCode = ByteReader.ReadByte();
                            KerbData.ErrorDesc = GetErrorDesc((ErrorCodes)KerbData.errorCode);
                            return;
                        }
                    default:
                        {
                            break;
                            //return;
                            //throw new Exception("Unexpected Tag" + TagID + " found in  KERB TCP response");
                        }
                }

            }
            while (TagID < 6 ); //Total 12 tags expected, but we are reading only 6 tags until error code

        }

        static void ParseErrorResponseUDP(KerberosData KerbData, TDSReader  ByteReader)
        {
            int TagID = 0, TagLen = 0;

            do
            {
                TagID = ByteReader.ReadByte() & (int)0x1F;
                TagLen = ReadAsnLen(ByteReader, false);

                switch (TagID)
                {
                    case 4: //skip Tag4->Stime,
                    case 5: //skip Tag5->SuSec
                        {
                            ByteReader.ReadBytes(TagLen); 
                            break;
                        }
                    case 6:
                        {
                            ReadAsnLen(ByteReader);
                            KerbData.errorCode = ByteReader.ReadByte();
                            KerbData.ErrorDesc = GetErrorDesc((ErrorCodes)KerbData.errorCode);
                            return;
                        }
                    default:
                        {
                            //throw new Exception("Unexpected Tag " + TagID + " found in  KERB UDP error response");
                            break;
                        }
                }

            }
            while (TagID < 6); //Total 12 tags expected, but we are reading only 6 tags until error code
        }

        static void GetVersion(KerberosData KerbData, TDSReader ByteReader)
        {
            int Length = ReadAsnLen(ByteReader);
            if (Length == 1)
                KerbData.Version = ByteReader.ReadByte();

            if ((Length != 1) || (KerbData.Version != 5))
                throw new Exception("Invalid Kerberos version and unexpected version or unexpected number of bytes are used for storing the version ");

        }

        public static KerberosData ProcessTCP(ConversationData c)
        {
            KerberosData KerbData = new KerberosData();
            KerbData.SourcePort = c.sourcePort;
            KerbData.convData = c;

            ReassembleFrames(c);
            foreach (FrameData fd in c.frames)
            {

                TDSReader ByteReader = null;

                if ((fd.payloadLength <= 1) && (fd.reassembledPayLoadLength <= 1))
                    continue;

                if ((fd.flags & (int) (TCPFlag.PUSH)) == 0)
                    continue;
                



                if (fd.reassembledPayLoad != null)
                    ByteReader = new TDSReader(fd.reassembledPayLoad, 0, -1, fd.reassembledPayLoad.Length);
                else
                    ByteReader = new TDSReader(fd.payload, 0, -1, fd.payloadLength);


                //Read or skip 4 bytes
                ByteReader.ReadByte();
                ByteReader.ReadByte();
                ByteReader.ReadByte();
                ByteReader.ReadByte();

                //Skip over 4 bytes 'ApplicationTag'
                ReadAsnLen(ByteReader);

                //Skip over 4 bytes 'KdcReq->SequenceHeader'
                ReadAsnLen(ByteReader);

                int Len2 = 0, TagLen = 0, TagID=0;
                string SPN = null;
               
                KerbData.convData = c;
                bool IsContinueToNextFrame = false;

                do
                {
                    TagID = ByteReader.ReadByte();
                    TagLen = ReadAsnLen(ByteReader, false);
                    TagID = TagID & 0x1F;


                    switch (TagID) //Lower 5 bits 
                    {
                        case 0: // Version# is in Tago in error response. 
                            {
                                GetVersion(KerbData, ByteReader);
                                break;
                            }

                        case 1:
                            {
                                //Tag1 contains request type for error and non-error response. 
                                //So, read the response type and break.
                                if (!fd.isFromClient) // could KERB error response or normal response
                                {
                                    GetMessageType(KerbData, ByteReader);
                                    KerbData.frameNo = fd.frameNo;
                                    KerbData.TimeStamp = new DateTime(((FrameData)c.frames[c.frames.Count - 1]).ticks).ToString(utility.TIME_FORMAT);
                                    if (KerbData.ResponseType == MessageTypes.KRB_ERROR)
                                    {
                                        
                                        //Console.WriteLine(fd.frameNo.ToString());
                                        ParseErrorResponseTCP(KerbData, ByteReader);
                                        
                                        IsContinueToNextFrame = true;

                                    }
                                    else if (KerbData.ResponseType == MessageTypes.KRB_TGS_REP)
                                    {
                                        //ParseNonErrorResponseTCP(KerbData, ByteReader);
                                        IsContinueToNextFrame = true;
                                        KerbData.ErrorDesc =  "No Error.";
                                    }

                                    //
                                    // Looks like a bug here if the Message type is not 12 or 13. e.g. in my trace, it is KRB_AS_REP (11)
                                    // We don't go down either of the above paths and then try to parse TAG 2 next time around the loop, which has a different meaning (padata) and then crash.
                                    //
                                    // Suggested fix:
                                    //
                                    else IsContinueToNextFrame = true; // must abort parsing if unexpected message type
                                    //

                                    break;
                                }
                                else
                                {
                                     GetVersion(KerbData, ByteReader); //Extract version# from KERB TCP request. 
                                     break;
                                }
                            }
                        case 2:
                            {
                                // Tag2 present only in the request and not in the response and error responses.
                                // Console.WriteLine(fd.frameNo.ToString());
                                if (GetMessageType(KerbData, ByteReader) != MessageTypes.KRB_TGS_REQ) return KerbData;  // if not a TGS_REQ, ignore rest of conversation and exit
                                    // IsContinueToNextFrame = true;
                                break;
                            }
                        case 3:
                            {
                                // skip the padata tag. Tag3 present in requet and response. 
                                //But we should not hit this case for response and only for request 
                                ByteReader.ReadBytes(TagLen); 
                                break;
                            }
                        case 4:
                            {

                                //Skip over 4 bytes 'SequenceHeader'
                                ReadAsnLen(ByteReader);
                                int Id2 = 0;
                                int TagNum = 0;
                                do
                                {
                                    Id2 = ByteReader.ReadByte();
                                    Len2 = ReadAsnLen(ByteReader, false);

                                    TagNum = Id2 & 0x1F;

                                    switch (TagNum)
                                    {
                                        case 0:
                                            {
                                                ByteReader.ReadByte();
                                                int Len3 = ReadAsnLen(ByteReader, false);

                                                //Read and skip 'padding'
                                                ByteReader.ReadBytes(Len3 - 4);

                                                KerbData.IsForwardable = (ByteReader.ReadByte() & 0x40) != 0;

                                                //Read remaining three bytes 
                                                ByteReader.ReadBytes(3);
                                                break;
                                            }
                                        case 1:
                                        case 2:
                                        case 4:
                                        case 5:
                                        case 7:
                                        case 8:
                                        case 9:
                                        case 10:
                                            {
                                                ByteReader.ReadBytes(Len2);
                                                break;
                                            }

                                        case 3:  // outer tag 4 inner tag 3 - Request:SNAME
                                            {
                                                ReadAsnLen(ByteReader); //Skip sequence header  of sname
                                                int Len3 = ReadAsnLen(ByteReader); //Skip Tag0  of sname
                                                //
                                                // Read the Name Type:
                                                //
                                                //  2 = NT-SRV-INST   - has two Strings: Service and Instance. '/' separater is implied
                                                // 10 = NT-ENTERPRISE - has one String
                                                //
                                                // Throw error on all other values
                                                //
                                                Len3 = ReadAsnLen(ByteReader);
                                                if (Len3 != 1) throw new Exception("Unexpected length (" + Len3 + ") reading SName Name Type.");
                                                byte NameType = ByteReader.ReadByte();
                                                KerbData.SNameType = NameType;
                                                //if (NameType != 2 && NameType != 10)
                                                //{
                                                //    IsContinueToNextFrame = true;
                                                //    break;
                                                //}

                                                ReadAsnLen(ByteReader); //Skip  Tag1 of sname
                                                Len3 = ReadAsnLen(ByteReader); //Skip sequenceheader  of sname.

                                                SPN = "";
                                                if (NameType == 2) // read service type
                                                {
                                                    Len3 = ReadAsnLen(ByteReader);
                                                    SPN = ByteReader.ReadAnsiString(Len3) + "/";
                                                }
                                                Len3 = ReadAsnLen(ByteReader); // read SPN length
                                                SPN += ByteReader.ReadAnsiString(Len3);
                                                KerbData.SPNRequested = SPN;
                                                //Console.WriteLine("SPN=\t" + SPN);
                                                break;
                                            }
                                        default:
                                            {
                                                //throw new Exception("Unexpected TAG (" + TagNum + ") found in the KERB TCP request, frame: " + fd.frameNo.ToString());
                                                break;
                                            }

                                    }

                                } while (TagNum < 3); //Because, we are reading only 1st three tags of requestbody and skip the rest 

                                break;
                            }
                        default:
                            {
                                // throw new Exception("Un expected tags in kerberos request/response/ problem in parseing");
                                break;
                            }
                    }
                }
                while ((TagID < 4) && (!IsContinueToNextFrame));

            }

            return KerbData;
        }

        public static KerberosData ProcessUDP(ConversationData c)
        {

            KerberosData KerbData = new KerberosData();
            KerbData.SourcePort = c.sourcePort;
            KerbData.convData = c;

            int Len2 = 0;
            int TagLen = 0;
            string SPN = null;
            int TagID = 0;

            bool IsContinueToNextFrame = false;

            foreach (FrameData fd in c.frames)
            {
                if (fd.payloadLength <= 1)
                    continue;


                TDSReader ByteReader = new TDSReader(fd.payload, 0, -1, fd.payloadLength);

                //Skip over 4 bytes 'ApplicationTag'
                ReadAsnLen(ByteReader);

                //Skip over 4 bytes 'KdcReq->SequenceHeader'
                ReadAsnLen(ByteReader);

                //Init vars after every frame processing 

                Len2 = 0;
                TagLen = 0;
                SPN = null;
                
                TagID = 0;

                do
                {
                    TagID = ByteReader.ReadByte();
                    TagLen = ReadAsnLen(ByteReader, false);

                    TagID = TagID & 0x1F;
                    switch (TagID) //Lower 5 bits 
                    {
                        case 0: // version# in Tag 0 for KRB_TGS_REP (response)
                        case 1:
                        case 2:
                            {
                                if ((fd.isFromClient && TagID == 1) || (!fd.isFromClient && TagID == 0))
                                    GetVersion(KerbData, ByteReader);
                                else if ((!fd.isFromClient && TagID == 1) || (fd.isFromClient && TagID == 2))
                                {
                                    MessageTypes MsgType = GetMessageType(KerbData, ByteReader);
                                    KerbData.frameNo = fd.frameNo;

                                    if (MsgType == MessageTypes.KRB_TGS_REP)
                                    {
                                        //ParseNonErrorResponseUDP(KerbData, ByteReader);
                                        IsContinueToNextFrame = true;
                                    }
                                    else if (MsgType == MessageTypes.KRB_ERROR)
                                    {
                                        ParseErrorResponseUDP(KerbData, ByteReader);
                                        IsContinueToNextFrame = true;
                                    }
                                }
                                break;
                            }
                        case 3:
                        
                            {
                                //ByteReader.ReadByte();
                                Len2 = ReadAsnLen(ByteReader);
                                ByteReader.ReadBytes(Len2); // skip the padata tag. 
                                break;
                            }
                        case 4:
                            {

                                //ByteReader.ReadByte(); //skip sequence header of ReqBody
                                ReadAsnLen(ByteReader);
                                int TagId2 = 0;
                                do
                                {
                                    TagId2 = ByteReader.ReadByte();
                                    Len2 = ReadAsnLen(ByteReader, false);
                                    TagId2 = TagId2 & 0x1F;
                                    switch (TagId2)
                                    {
                                        case 0:
                                            {
                                                ByteReader.ReadByte();
                                                int Len3 = ReadAsnLen(ByteReader, false);

                                                //Read and skip 'padding'
                                                ByteReader.ReadBytes(Len3 - 4);

                                                KerbData.IsForwardable = (ByteReader.ReadByte() & 0x40) != 0;

                                                //Read remaining three bytes 
                                                ByteReader.ReadBytes(3);
                                                break;
                                            }
                                        case 1:
                                        case 2:
                                        case 4:
                                        case 5:
                                        case 7:
                                        case 8://skip these tags. 
                                            {
                                                ByteReader.ReadBytes(Len2);
                                                break;
                                            }

                                        case 3:
                                            {
                                                
                                                // UDP SName implementation - replacing with TCP implementation
                                                
                                                // ReadAsnLen(ByteReader);             //Skip sequence header  of sname
                                                // int Len3 = ReadAsnLen(ByteReader);  //Skip Tag0  of sname
                                                // ByteReader.ReadBytes(Len3);         //skip nametype 
                                                // ReadAsnLen(ByteReader);             //Skip  Tag1 of sname
                                                // Len3 = ReadAsnLen(ByteReader);      //Skip sequence header  of sname->Tag1
                                                // Len3 = ReadAsnLen(ByteReader);      // Read SPN Length - same as the TCP implementation
                                                // SPN = ByteReader.ReadAnsiString(Len3);
                                                // KerbData.SPNRequested = SPN;

                                                // TCP SName implementation

                                                ReadAsnLen(ByteReader); //Skip sequence header  of sname
                                                int Len3 = ReadAsnLen(ByteReader); //Skip Tag0  of sname
                                                //
                                                // Read the Name Type:
                                                //
                                                //  2 = NT-SRV-INST   - has two Strings: Service and Instance. '/' separater is implied
                                                // 10 = NT-ENTERPRISE - has one String
                                                //
                                                // Throw error on all other values
                                                //
                                                Len3 = ReadAsnLen(ByteReader);
                                                if (Len3 != 1) throw new Exception("Unexpected length (" + Len3 + ") reading SName Name Type.");
                                                byte NameType = ByteReader.ReadByte();
                                                KerbData.SNameType = NameType;
                                                if (NameType != 2 && NameType != 10)
                                                {
                                                    IsContinueToNextFrame = true;
                                                    break;
                                                }

                                                ReadAsnLen(ByteReader); //Skip  Tag1 of sname
                                                Len3 = ReadAsnLen(ByteReader); //Skip sequenceheader  of sname.

                                                SPN = "";
                                                if (NameType == 2) // read service type
                                                {
                                                    Len3 = ReadAsnLen(ByteReader);
                                                    SPN = ByteReader.ReadAnsiString(Len3) + "/";
                                                }
                                                Len3 = ReadAsnLen(ByteReader); // read SPN length
                                                SPN += ByteReader.ReadAnsiString(Len3);
                                                KerbData.SPNRequested = SPN;

                                                break;
                                            }
                                        default:
                                            {
                                                throw new Exception("Unknonw tag in kerberos packet");
                                            }
                                    }

                                } while (TagId2 <3);

                                break;
                            }
                        default:
                            {
                                // throw new Exception("Un expected tags in kerberos request/response/ problem in parseing");
                                break;
                            }
                    }
                }
                while ((TagID  < 4) && (!IsContinueToNextFrame));
            }

            return KerbData;

        }

        public static void Process(NetworkTrace trace)
        {

            foreach (ConversationData c in trace.conversations)
            {
                if (c.sourcePort == 88)
                    TDSParser.reverseSourceDest(c);


                if (c.destPort != 88) 
                    continue;

              
                KerberosData KerbData = null;

                try
                {
                    if (c.isUDP) // UDP
                    {
                        KerbData = ProcessUDP(c);
                    }
                    else        // TCP
                    {
                        KerbData = ProcessTCP(c);
                    }
                    // ignore non KRB_TGS requests
                    // ignore responses without an associated request - we don't want to log errors for unidentified request types
                    // ignore SNames we don't know what they are ... or how to read them
                    //if (KerbData.RequestType == MessageTypes.KRB_TGS_REQ
                    //   && (KerbData.SNameType == 2 || KerbData.SNameType == 10))
                    if (KerbData.RequestType == MessageTypes.KRB_TGS_REQ)
                    {
                        trace.KerbResponses.Add(KerbData);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception during Kerberos processing." + "\r\n" + ex.Message + "\r\n" + ex.StackTrace);
                    Program.logDiagnostic("Exception during Kerberos processing." + "\r\n" + ex.Message + "\r\n" + ex.StackTrace);
                } // catch
            } // foreach
        } // void Process(...)
    }
}
