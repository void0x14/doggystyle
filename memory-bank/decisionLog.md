# Decision Log: Ghost Engine Architecture

## Architecting Logic
All decisions prioritize fingerprint alignment over standard library conveniences to ensure 100% manual control of packet headers.

## Key Decisions
### 1. Raw Sockets: IPPROTO_RAW (Linux)
- **Problem**: Layer 2 (AF_PACKET) is too manual (MAC addresses required), while Layer 4 (SOCK_STREAM) prevents header control.
- **Decision**: Use `IPPROTO_RAW` to control IP and TCP headers while letting the OS handle the interface/MAC layer.
- **Impact**: Full JA4T alignment.

### 2. RST Suppression (Linux)
- **Problem**: Host OS kernel kills manual TCP connections on non-bound ports with RST packets.
- **Decision**: Use `iptables` to block OUTBOUND RST packets on the source port during the handshake.
- **Impact**: Allows 3-way handshake to complete without kernel interference.

### 3. Dynamic Local IP Hooking
- **Problem**: Hardcoded local IPs are unreliable and detectable.
- **Decision**: Use `ioctl` (SIOCGIFADDR) on Linux to dynamically discover the host IPv4.
- **Impact**: Correct pseudo-header calculations for checksums and genuine source-IP signatures.

### 4. JA4/JA4T Alignment Matrix
- **Problem**: Universal signatures are easily flagged.
- **Decision**: Implement OS-specific TTLs (64 for Linux, 128 for Windows) and distinct TCP option sequences.
- **Impact**: Indistinguishability from legitimate browser processes on the same host.

### 5. PacketWriter Strategy
- **Problem**: Manual buffer indexing and pointer arithmetic lead to memory overflows and brittle code.
- **Decision**: Create a `PacketWriter` struct that tracks index and uses `std.debug.assert` for every write operation.
- **Impact**: Fail-fast memory safety during development and atomic packet construction.

### 6. TLS Record Layer Wrapping
- **Problem**: Sending raw Handshake payloads without a Record Header caused servers to drop packets.
- **Decision**: Explicitly wrap Client Hello in a 5-byte TLS Record Layer (0x16 0x03 0x01).
- **Impact**: Successful JA4S communication and handshake completion.
