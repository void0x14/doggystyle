# Active Context: Scaling to OS-Truth

## Current Work
Implementing dynamic OS-specific network signatures (JA4/JA4T) and ensuring handshake stability through manual ACK injection.

## Recent Decisions
- **JA4S Verification Loop**: Refactored to dynamically calculate TCP Data Offset, correctly handling variable-length TCP options (e.g., Timestamps) for Server Hello parsing.
- **TLS Record Layer**: Added missing 5-byte Record Header (0x16 0x03 0x01 + 2-byte Length) to Client Hello to prevent server-side rejection.
- **PacketWriter Discipline**: Introduced `PacketWriter` struct with `std.debug.assert` bounds checking for all packet construction to replace manual buffer management.
- **MTU/DF Handling**: Cleared the IP `Don't Fragment` (DF) bit and increased `tls_client_hello_mss_limit` to 1500 to handle larger packets/fragmentation gracefully.

## Open Questions/Tasks
- **Windows Porting**: Implementation for `getInterfaceIp` and `WindowsRawSocket` is pending.
- **Memory Safety Hardening**: Continue replacing manual pointer arithmetic with `PacketWriter` methods across the engine.
- **TLS Extensions**: Further refinement of extension order (SNI, ALPN, Renegotiation, etc.) to match Chrome exactly.
