# Product Context: Stealth Network Engine

## Why This Exists?
Modern network security (Cloudflare, Akamai, AWS) uses fingerprinting to identify bots quickly by observing characteristics like:
- **TTL**: Legitimate browser traffic on Linux has a default TTL of 64, while on Windows it's 128.
- **Window Size**: Fixed or calculated sizes vary by OS.
- **TCP Options Sequence**: Chrome on Linux and Chrome on Windows use different orderings for MSS, SACK, TS, and WS.
- **TLS Client Hello**: Ciphers, extensions, and their order reveal the underlying OS and browser version.

## Key Experiences
The user wants a seamless, "silent" connection experience where the engine handles all low-level handshake logic manually to avoid OS-kernel interference (RST packets) and ensures every bit in the TCP/IP/TLS headers aligns with the "OS-Truth".

## User Personas
- **Senior Systems Architect**: Focused on performance and reliability of the handshake.
- **Network Security Engineer**: Focused on evasion and fingerprinting alignment.
