using System;

namespace SQLNA
{
    class TLS
    {
        public bool truncated = false;
        public int bytesRead = 0;
        public ushort sslLevel = 0;
        public ushort Length = 0;
        public string TDSVerstion = "";
        public TLSRecLayer1HandShake handshake = null;
        public TLSRecLayer2CipherChangeSpec cipherChangeSpec = null;
        public TLSRecLayer3ApplicationData applicationData = null;

        public static TLS Parse(byte[] Payload, int offset)
        {
            TLS tls = new TLS();

            // do we have any bytes to read ?
            if (offset >= Payload.Length)
            {
                tls.truncated = true;
                return tls;
            }

            // process payload with 1-3 tokens - just process the first token
            // while (offset < Payload.Length)
            {
                switch (Payload[offset])
                {
                    case 0x14: // cipher change spec
                        tls.cipherChangeSpec = TLSRecLayer2CipherChangeSpec.Parse(Payload, offset);  // not with client hello
                        if (tls.cipherChangeSpec == null) return null;
                        offset += tls.cipherChangeSpec.bytesRead;
                        tls.bytesRead += tls.cipherChangeSpec.bytesRead;
                        tls.truncated = tls.cipherChangeSpec.truncated;
                        break;
                    case 0x15: // encrypted alert
                        // what's the impplementation ?
                        throw new Exception("Unexpected TLS token value 0x15 - Encrypted Alert.");
                    // break;
                    case 0x16: // handshake
                        tls.handshake = TLSRecLayer1HandShake.Parse(Payload, offset);  // can have client hello or server hello
                        if (tls.handshake == null) return null;
                        offset += tls.handshake.bytesRead;
                        tls.bytesRead += tls.handshake.bytesRead;
                        tls.truncated = tls.handshake.truncated;
                        break;
                    case 0x17: // application data
                        tls.applicationData = TLSRecLayer3ApplicationData.Parse(Payload, offset);  // not with client hello
                        if (tls.applicationData == null) return null;
                        offset += tls.applicationData.bytesRead;
                        tls.bytesRead += tls.applicationData.bytesRead;
                        tls.truncated = tls.applicationData.truncated;
                        break;
                    default:
                        // unknown token value
                        // throw new Exception($"Unexpected token value {Payload[offset]} - Unknown Content Type.");
                        return null;
                }
                // if (tls.truncated) break;  // use only if the while loop is reinstated
            }
            return tls;
        }

        public bool hasHandshake { get { return (handshake != null && handshake.bytesRead != 0); } }
        public bool hasCipherChangeSpec { get { return (cipherChangeSpec != null && cipherChangeSpec.bytesRead != 0); } }
        public bool hasApplicationData { get { return (applicationData != null && applicationData.bytesRead != 0); } }

        public bool hasTDS8
        {
            get
            {
                if (hasHandshake) return handshake.hasTDS8;
                return false;
            }
        }
    }

    public class TLSRecLayer1HandShake
    {
        public bool truncated = false;
        public int bytesRead = 0;
        public ushort sslLevel = 0;
        public ushort Length = 0;
        public TLSClientHelloToken clientHello = null;
        public TLSServerHelloToken serverHello = null;
        public bool hasClientKeyExchange = false;

        public static TLSRecLayer1HandShake Parse(byte[] Payload, int offset)
        {
            TLSRecLayer1HandShake handshake = new TLSRecLayer1HandShake();
            int originalOffset = offset;

            try
            {
                offset++;                                                                           // skip 0x16 token byte
                handshake.sslLevel = utility.B2UInt16(Payload, offset); offset += 2;
                if (!utility.ValidSSLVersion(handshake.sslLevel)) return null;                      // validate the version # otherwise garbage
                handshake.Length = utility.B2UInt16(Payload, offset); offset += 2;
                // offset += handshake.Length;                                                         // skip bytes

                switch (Payload[offset])
                {
                    case 0x01: // client hello
                        handshake.clientHello = TLSClientHelloToken.Parse(Payload, offset);  // not with client hello
                        if (handshake.clientHello == null) return null;
                        offset += handshake.clientHello.bytesRead;
                        handshake.bytesRead += handshake.clientHello.bytesRead;
                        handshake.truncated = handshake.clientHello.truncated;
                        break;
                    case 0x02: // server hello
                        handshake.serverHello = TLSServerHelloToken.Parse(Payload, offset);  // can have client hello or server hello
                        if (handshake.serverHello == null) return null;
                        offset += handshake.serverHello.bytesRead;
                        handshake.bytesRead += handshake.serverHello.bytesRead;
                        handshake.truncated = handshake.serverHello.truncated;
                        break;
                    case 0x10: // client key exchange
                        handshake.hasClientKeyExchange = true;
                        break;
                    default:
                        // unknown token value
                        // throw new Exception($"Unexpected TLS handshake token value {Payload[offset]}.");
                        // break;
                        return null;
                }
                handshake.bytesRead = offset - originalOffset;
            }
            catch (IndexOutOfRangeException)
            {
                handshake.truncated = true;
            }
            return handshake;
        }

        public bool hasClientHello { get { return (clientHello != null && clientHello.bytesRead != 0); } }
        public bool hasServerHello { get { return (serverHello != null && serverHello.bytesRead != 0); } }

        public bool hasTDS8
        {
            get
            {
                if (hasClientHello && clientHello.ALPN == "tds/8.0") return true;
                if (hasServerHello && serverHello.ALPN == "tds/8.0") return true;
                return false;
            }
        }

    }

    public class TLSRecLayer2CipherChangeSpec
    {
        public bool truncated = false;
        public int bytesRead = 0;
        public ushort sslLevel = 0;
        public ushort Length = 0;


        public static TLSRecLayer2CipherChangeSpec Parse(byte[] Payload, int offset)
        {
            TLSRecLayer2CipherChangeSpec ccs = new TLSRecLayer2CipherChangeSpec();
            int originalOffset = offset;

            try
            {
                offset++;                                                                     // skip 0x14 token byte
                ccs.sslLevel = utility.B2UInt16(Payload, offset); offset += 2;
                if (!utility.ValidSSLVersion(ccs.sslLevel)) return null;                      // validate the version # otherwise garbage
                ccs.Length = utility.B2UInt16(Payload, offset); offset += 2;
                offset += ccs.Length;                                                         // skip bytes
                ccs.bytesRead = offset - originalOffset;
            }
            catch (IndexOutOfRangeException)
            {
                ccs.truncated = true;
            }
            return ccs;
        }
    }

    public class TLSRecLayer3ApplicationData
    {
        public bool truncated = false;
        public int bytesRead = 0;
        public ushort sslLevel = 0;
        public ushort Length = 0;

        public static TLSRecLayer3ApplicationData Parse(byte[] Payload, int offset)
        {
            TLSRecLayer3ApplicationData appData = new TLSRecLayer3ApplicationData();
            int originalOffset = offset;

            try
            {
                offset++;                                                                         // skip 0x17 token byte
                appData.sslLevel = utility.B2UInt16(Payload, offset); offset += 2;
                if (!utility.ValidSSLVersion(appData.sslLevel)) return null;                      // validate the version # otherwise garbage
                appData.Length = utility.B2UInt16(Payload, offset); offset += 2;
                offset += appData.Length;                                                         // skip bytes
                appData.bytesRead = offset - originalOffset;
            }
            catch (IndexOutOfRangeException)
            {
                appData.truncated = true;
            }
            return appData;
        }
    }

    public class TLSClientHelloToken
    {
        public bool truncated = false;
        public int bytesRead = 0;
        public uint Length = 0;                                                                      // Length is 3 bytes and comes before SSL version
        public ushort sslLevel = 0;
        public string serverName = "";
        public string ALPN = "";

        public static TLSClientHelloToken Parse(byte[] Payload, int offset)
        {
            TLSClientHelloToken ch = new TLSClientHelloToken();
            int originalOffset = offset;

            try
            {
                // read header bytes
                offset++;                                                                            // skip 0x01 token byte
                byte hiLength = Payload[offset]; offset++;               // length is 3 bytes, this is MSB
                if (hiLength != 0) return null;                                                      // hiLength should always be 0 since the encapsulating handshake length is only 2 bytes
                ch.Length = utility.B2UInt16(Payload, offset) + (uint)(hiLength * 0x10000); offset += 2;            // length is 3 bytes - add hiLength (0) for corectness
                ch.sslLevel = utility.B2UInt16(Payload, offset); offset += 2;
                if (!utility.ValidSSLVersion(ch.sslLevel)) return null;                              // validate the version # otherwise garbage

                // skip random bytes and session id
                offset += 32;                                                                        // random bytes are 32 bytes always
                byte sessionIDLength = Payload[offset]; offset++;
                offset += sessionIDLength;                                                           // it's in bytes, not int or some record size

                // skip cipher suites
                ushort cipherSuitesLength = utility.B2UInt16(Payload, offset); offset += 2;
                offset += cipherSuitesLength;                                                        // skip this many bytes, not cipher suites (2-bytes each)

                // skip compression methods
                byte compressionMethodLength = Payload[offset]; offset++;
                offset += compressionMethodLength;                                                   // skip this many bytes

                // read extension methods
                ushort extensionMethodsLength = utility.B2UInt16(Payload, offset); offset += 2;
                int startOffset = offset;                                                            // byte 0 of the extension methods comes after the length
                while (offset < startOffset + extensionMethodsLength)
                {
                    // read one extension method
                    // read extension method header
                    ushort extensionType = utility.B2UInt16(Payload, offset); offset += 2;
                    ushort extensionLength = utility.B2UInt16(Payload, offset); offset += 2;
                    switch (extensionType)
                    {
                        case 0x0000: // host name - can have several records
                            {
                                int listStartOffset = offset;
                                ushort listLength = utility.B2UInt16(Payload, offset); offset += 2;
                                while (offset < listStartOffset + listLength)
                                {
                                    // read one server name record - host name = type 0
                                    byte nameType = Payload[offset]; offset++;
                                    ushort nameLength = utility.B2UInt16(Payload, offset); offset += 2;
                                    if (nameType == 0) ch.serverName = utility.ReadAnsiString(Payload, offset, nameLength);
                                    offset += nameLength; // whether we read the name or skip the name
                                }
                                // check the math
                                if (offset != listStartOffset + extensionLength) throw new InvalidOperationException($"Server Name Extension list length is corrupt. Offset {offset} != list offset {listStartOffset} + extension length {extensionLength}. Extension type {extensionType}.");
                            }
                            break;
                        case 0x0010: // ALPN - can have several records
                            {
                                int listStartOffset = offset;
                                ushort listLength = utility.B2UInt16(Payload, offset); offset += 2;
                                while (offset < listStartOffset + listLength)
                                {
                                    // read one server name record - no type indicator
                                    byte nameLength = Payload[offset]; offset++;
                                    if (ch.ALPN == "") ch.ALPN = utility.ReadAnsiString(Payload, offset, nameLength);  // only record the first one
                                    offset += nameLength; // whether we read the name or skip the name
                                }
                                // check the math
                                if (offset != listStartOffset + extensionLength) throw new InvalidOperationException($"ALPN Extension list length is corrupt. Offset {offset} != list offset {listStartOffset} + extension length {extensionLength}. Extension type {extensionType}.");
                            }
                            break;
                        default:     // bypass other extension methods
                            offset += extensionLength;                                               // the extensionLength does not include the 4 bytes for type and length, just what comes after
                            break;
                    }
                }
                // check the math
                if (offset != startOffset + extensionMethodsLength) throw new InvalidOperationException($"Overall Extension list length is corrupt. Offset {offset} != list offset {startOffset} + extension length {extensionMethodsLength}.");
                ch.bytesRead = offset - originalOffset;
            }
            catch (IndexOutOfRangeException)
            {
                ch.truncated = true;
            }

            return ch;
        }
    }

    public class TLSServerHelloToken
    {
        public bool truncated = false;
        public int bytesRead = 0;
        public uint Length = 0;                                                                      // Length is 3 bytes and comes before SSL version
        public ushort sslLevel = 0;
        public ushort cipherSuite = 0;
        public string serverName = "";
        public string ALPN = "";

        public static TLSServerHelloToken Parse(byte[] Payload, int offset)
        {
            TLSServerHelloToken sh = new TLSServerHelloToken();
            int originalOffset = offset;

            try
            {
                // read header bytes
                offset++;                                                                            // skip 0x02 token byte
                byte hiLength = Payload[offset]; offset++;               // length is 3 bytes, this is MSB
                if (hiLength != 0) return null;                                                      // hiLength should always be 0 since the encapsulating handshake length is only 2 bytes
                sh.Length = utility.B2UInt16(Payload, offset) + (uint)(hiLength * 0x10000); offset += 2;            // length is 3 bytes - add hiLength (0) for corectness
                sh.sslLevel = utility.B2UInt16(Payload, offset); offset += 2;
                if (!utility.ValidSSLVersion(sh.sslLevel)) return null;                              // validate the version # otherwise garbage

                // skip random bytes and session id
                offset += 32;                                                                        // random bytes are 32 bytes always
                byte sessionIDLength = Payload[offset]; offset++;
                offset += sessionIDLength;                                                           // it's in bytes, not int or some record size

                // read the cipher suite chosen
                sh.cipherSuite = utility.B2UInt16(Payload, offset); offset += 2;

                // skip compression method chosen
                offset++;

                // read extension methods
                ushort extensionMethodsLength = utility.B2UInt16(Payload, offset); offset += 2;
                int startOffset = offset;                                                            // byte 0 of the extension methods comes after the length
                while (offset < startOffset + extensionMethodsLength)
                {
                    // read one extension method
                    // read extension method header
                    ushort extensionType = utility.B2UInt16(Payload, offset); offset += 2;
                    ushort extensionLength = utility.B2UInt16(Payload, offset); offset += 2;
                    switch (extensionType)
                    {
                        case 0x0000: // host name - can have several records
                            {
                                int listStartOffset = offset;
                                ushort listLength = utility.B2UInt16(Payload, offset); offset += 2;
                                while (offset < listStartOffset + listLength)
                                {
                                    // read one server name record - host name = type 0
                                    byte nameType = Payload[offset]; offset++;
                                    ushort nameLength = utility.B2UInt16(Payload, offset); offset += 2;
                                    if (nameType == 0) sh.serverName = utility.ReadAnsiString(Payload, offset, nameLength);
                                    offset += nameLength; // whether we read the name or skip the name
                                }
                                // check the math
                                if (offset != listStartOffset + extensionLength) throw new InvalidOperationException($"Server Name Extension list length is corrupt. Offset {offset} != list offset {listStartOffset} + extension length {extensionLength}. Extension type {extensionType}.");
                            }
                            break;
                        case 0x0010: // ALPN - can have several records
                            {
                                int listStartOffset = offset;
                                ushort listLength = utility.B2UInt16(Payload, offset); offset += 2;
                                while (offset < listStartOffset + listLength)
                                {
                                    // read one server name record - no type indicator
                                    byte nameLength = Payload[offset]; offset++;
                                    if (sh.ALPN == "") sh.ALPN = utility.ReadAnsiString(Payload, offset, nameLength);  // only record the first one
                                    offset += nameLength; // whether we read the name or skip the name
                                }
                                // check the math
                                if (offset != listStartOffset + extensionLength) throw new InvalidOperationException($"ALPN Extension list length is corrupt. Offset {offset} != list offset {listStartOffset} + extension length {extensionLength}. Extension type {extensionType}.");
                            }
                            break;
                        default:     // bypass other extension methods
                            offset += extensionLength;                                               // the extensionLength does not include the 4 bytes for type and length, just what comes after
                            break;
                    }
                }
                // check the math
                if (offset != startOffset + extensionMethodsLength) throw new InvalidOperationException($"Overall Extension list length is corrupt. Offset {offset} != list offset {startOffset} + extension length {extensionMethodsLength}.");
                sh.bytesRead = offset - originalOffset;
            }
            catch (IndexOutOfRangeException)
            {
                sh.truncated = true;
            }

            return sh;

        }
    }
}
