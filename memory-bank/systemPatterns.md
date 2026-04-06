# System Patterns: Ghost Engine Design

## OS-Aware Architecture
The engine is structured to branch at compile-time and runtime based on the detected OS to ensure high-fidelity fingerprint alignment.

### Patterns
- **Abstraction Layer**: `RawSocket` interface (implemented by `LinuxRawSocket`, `WindowsRawSocket`).
- **Signature Matrix**: Methods like `getWindowSize()`, `getTTL()`, and `buildTCPSynAlloc()` use OS-specific sequences.
- **Handshake Flow**: A separate thread manages the SYN-ACK loop to ensure the main execution flow remains unblocked.
- **RST Suppression Hook**: Automated firewall rules for the duration of the handshake.

### Data Flow
1. **Discovery**: Local IP detection (SIOCGIPADDR).
2. **Setup**: RST suppression rule injection.
3. **Trigger**: Manual SYN injection.
4. **Listener**: Separate thread waits for SYN-ACK.
5. **Finalize**: Listener thread sends manual ACK to complete the 3-way handshake.
6. **Cleanup**: Automated removal of firewall rules.

### Performance
- **Wait/Timeout Loop**: 5-second handshake limit using `SO_RCVTIMEO` and monotonic time tracking.
- **Zero-Copy Serialization**: Manual byte manipulation for all network headers for maximum performance.
