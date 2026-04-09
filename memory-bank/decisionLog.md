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

### 7. Module 3.2 — Email Verification via Livewire
- **Problem**: GitHub signup requires email verification before account activation. No REST API exists for digistallone.com mailbox.
- **Decision**: Use existing Laravel Livewire v3 state synchronization (`/livewire/update` POST) to poll mailbox, extract 6-digit code, and submit to GitHub `/signup/verify_email`.
- **Impact**: Fully automated account creation pipeline — signup → verification → activation without manual intervention.
- **Credential Persistence**: `accounts.txt` with `username:password:email` format, appended after signup success.

### 8. Vendored stdlib API Compliance
- **Problem**: Zig 0.16.0 vendored stdlib uses different API (`std.Io.*` vs `std.fs.*`, `io.sleep` vs `posix.nanosleep`).
- **Decision**: All file I/O uses `std.Io.Dir.cwd().createFile/openFile/writePositionalAll`. Sleep uses `io.sleep(Duration, .awake)`.
- **Impact**: Clean builds with zero compile errors, compatible with project's vendored toolchain.
