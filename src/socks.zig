const socks = @This();

//SOCKS4
//VER: 8 bits SOCKS version number, 0x04 for this version
//CMD: 8 bits Command code:
//        0x01: Establish a TCP/IP stream connection.
//        0x02: Establish a TCP/IP port binding.
//DSTPORT: 16 bits Destination port number, in network byte order.
//DESTIP: 32 bits Destination IPv4 address, in network byte order.
//ID: variable The User ID string, null-terminated.
//
//The server responds with:
//VN: 8 bits Reply version (a null byte).
//REP: 8 bits Reply code:
//        0x5a: Request granted.
//        0x5b: Request rejected or failed.
//        0x5c: Request failed because client is not running identd (or not reachable from server).
//        0x5d: Request failed because client's identd could not confirm the user ID in the request.
//DSTPORT: 16 bits Destination port number, meaningful if granted in BIND, should otherwise be ignored.
//DESTIP: 32 bits Destination IPv4 address. Together with DSTPORT the ip:port the client should bind to.
//
//For example, this is a SOCKS4 request to connect Fred to 66.102.7.99:80, the server replies with an "OK":
//    Client: 0x04 | 0x01 | 0x00 0x50 | 0x42 0x66 0x07 0x63 | 0x46 0x72 0x65 0x64 0x00
//        The last field is "Fred" in ASCII, followed by a null byte.
//    Server: 0x00 | 0x5A | 0xXX 0xXX | 0xXX 0xXX 0xXX 0xXX
//        0xXX can be any byte value. The SOCKS4 protocol specifies that the values of these
//        bytes should be ignored.
//
//From this point onwards, any data sent from the SOCKS client to the SOCKS
//server is relayed to 66.102.7.99, and vice versa.
//
//The command field may be 0x01 for "connect" or 0x02 for "bind"; the "bind"
//command allows incoming connections for protocols such as active FTP.
//
//SOCKS4a extends the SOCKS4 protocol to allow a client to specify a destination
//domain name rather than an IP address; this is useful when the client itself
//cannot resolve the destination host's domain name to an IP address. It was
//proposed by Ying-Da Lee, the author of SOCKS4.[16]
//
//The client should set the first three bytes of DSTIP to NULL and the last byte
//to a non-zero value. (This corresponds to IP address 0.0.0.x, with x nonzero,
//an inadmissible destination address and thus should never occur if the client
//can resolve the domain name.) Following the NULL byte terminating USERID, the
//client must send the destination domain name and terminate it with another
//NULL byte. This is used for both "connect" and "bind" requests.
//
//Client to SOCKS server:
//First packet to server     SOCKS4_C     DOMAIN
//  SOCKS4_C SOCKS4 client handshake packet (above)
//  DOMAIN the domain name of the host to contact , null (0x00) terminated
//
//Server to SOCKS client: (Same as SOCKS4)
//A server using protocol SOCKS4a must check the DSTIP in the request packet. If
//it represents address 0.0.0.x with nonzero x, the server must read in the
//domain name that the client sends in the packet. The server should resolve the
//domain name and make connection to the destination host if it can.

pub const v4 = struct {
    pub const Request = struct {
        version: u8 = 4,
        command: u8,
        dstport: u16,
        dstaddr: u32,
        id: [:0]const u8,
    };

    pub const Reply = struct {
        version: u8 = 4,
        reply: u8,
        dstport: u16,
        dstaddr: u32,
    };

    pub const v4a = struct {};
};

pub const v5 = struct {
    pub const Greeting = struct {
        version: u8,
        num_auth: u8,
        auth: []const Auth.Method,

        /// ServerChoice
        pub const Choice = struct {
            version: u8,
            auth: Auth.Method,
        };

        pub const Auth = struct {
            version: u8,
            id_len: u8,
            /// RFC: 0 <= len <= 255
            id: []const u8,
            pw_len: u8,
            /// RFC: 0 <= len <= 255
            pw: []const u8,

            pub const Response = struct {
                version: u8,
                status: u8,
            };

            pub const Method = enum(u8) {
                none = 0x00,
                gssapi = 0x01,
                userpass = 0x02,
                challenge_handshake = 0x03,
                unassigned = 0x04,
                challenge_response = 0x05,
                ssl = 0x06,
                nds = 0x07,
                multi_auth_framework = 0x08,
                json = 0x09,
                _,
                // 0x03–0x7F: methods assigned by IANA
                // 0x0A–0x7F: Unassigned
                // 0x80–0xFE: methods reserved for private use
            };
        };
    };

    pub const Connection = struct {
        version: u8 = 5,
        command: u8,
        /// RFC: must be zero
        reserved: u8 = 0,
        addr: Address,
        port: u16,

        pub const Command = enum(u8) {
            tcp_stream = 0x01,
            tcp_port = 0x02,
            udp_port = 0x03,
        };

        pub const Address = union(Flavor) {
            v4: u32,
            /// RFC: 0 <= len <= 255
            domain: []const u8,
            v6: u128,

            pub const Flavor = enum(u8) {
                v4 = 0x01,
                domain = 0x03,
                v6 = 0x04,
            };
        };

        pub const Answer = struct {
            version: u8 = 5,
            status: Status,
            /// RFC: must be zero
            reserved: u8 = 0,
            addr: Address,
            port: u16,

            pub const Status = enum(u8) {
                granted = 0x00,
                failure = 0x01,
                not_allowed = 0x02,
                network_unreachable = 0x03,
                host_unreachable = 0x04,
                connection_refused_by_dest = 0x05,
                ttl = 0x06,
                protocol_err = 0x07,
                addr_not_supported = 0x08,
            };
        };
    };
};

//SOCKS5
//The SOCKS5 protocol is defined in RFC 1928. It is an incompatible extension of
//the SOCKS4 protocol; it offers more choices for authentication and adds
//support for IPv6 and UDP, the latter of which can be used for DNS lookups. The
//initial handshake consists of the following:
//
//    Client connects and sends a greeting, which includes a list of authentication methods supported.
//    Server chooses one of the methods (or sends a failure response if none of them are acceptable).
//    Several messages may now pass between the client and the server, depending
//        on the authentication method chosen. Client sends a connection request
//        similar to SOCKS4.
//    Server responds similar to SOCKS4.
//
//The initial greeting from the client is:
//Client greeting     VER     NAUTH     AUTH
//  VER SOCKS version (0x05)
//  NAUTH Number of authentication methods supported, uint8
//  AUTH Authentication methods, 1 byte per method supported
//
//Server choice     VER     CAUTH
//  VER SOCKS version (0x05)
//  CAUTH chosen authentication method, or 0xFF if no acceptable methods were offered
//
//The subsequent authentication is method-dependent. Username and password
//authentication (method 0x02) is described in RFC 1929: Client authentication
//request, 0x02     VER     IDLEN     ID     PWLEN     PW
//Byte count     1     1     (1–255)     1     (1–255)
//
//VER 0x01 for current version of username/password authentication
//IDLEN, ID Username length, uint8; username as bytestring
//PWLEN, PW Password length, uint8; password as bytestring
//
//Server response, 0x02     VER     STATUS
//  VER 0x01 for current version of username/password authentication
//  STATUS 0x00 success, otherwise failure, connection must be closed
//
//After authentication the connection can proceed. We first define an address datatype as:
//SOCKS5 address     TYPE     ADDR
//TYPE type of the address. One of:
//        0x01: IPv4 address
//        0x03: Domain name
//        0x04: IPv6 address
//
//ADDR the address data that follows. Depending on type:
//        4 bytes for IPv4 address
//        1 byte of name length followed by 1–255 bytes for the domain name
//        16 bytes for IPv6 address
//
//Client connection request     VER     CMD     RSV     DSTADDR     DSTPORT
//  VER SOCKS version (0x05)
//  CMD command code:
//          0x01: establish a TCP/IP stream connection
//          0x02: establish a TCP/IP port binding
//          0x03: associate a UDP port
//  RSV reserved, must be 0x00
//DSTADDR destination address, see the address structure above.
//DSTPORT port number in a network byte order
//
//Response packet from server     VER     STATUS     RSV     BNDADDR     BNDPORT
// VER SOCKS version (0x05)
//STATUS status code:
//        0x00: request granted
//        0x01: general failure
//        0x02: connection not allowed by ruleset
//        0x03: network unreachable
//        0x04: host unreachable
//        0x05: connection refused by destination host
//        0x06: TTL expired
//        0x07: command not supported / protocol error
//        0x08: address type not supported
//RSV reserved, must be 0x00
//BNDADDR server bound address in the "SOCKS5 address" format specified above
//BNDPORT server bound port number in a network byte order
//
//Since clients are allowed to use either resolved addresses or domain names, a
//convention from cURL exists to label the domain name variant of SOCKS5
//"socks5h", and the other simply "socks5". A similar convention exists between
//SOCKS4a and SOCKS4.[18]
