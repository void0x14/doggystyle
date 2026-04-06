# Project Brief: Ghost Engine

## Overview
A zero-dependency, high-stealth network engine written in Zig 0.16. Its primary purpose is to bypass modern network fingerprinting (JA4/JA4T/JA4S) and behavioral analysis during automated operations.

## Core Objectives
- **Full Contextual Alignment**: The engine must be indistinguishable from a legitimate browser on the host OS.
- **Zero-Dependency**: Do not rely on external libraries for socket operations or TLS.
- **RST Suppression**: Take control of the local networking stack to prevent kernel-level interference with manual handshakes.
- **Contextual TCP Signatures (JA4T)**: Match TTL, Window Size, and TCP Options with the host OS.
- **TLS Fingerprint Alignment (JA4)**: Match Client Hello structure, ciphers, and extensions with host browser patterns.

## Technical Requirements
- Language: Zig 0.16
- Platforms: Linux (Primary), Windows (Target)
- Network Layer: Layer 3 (Raw IP sockets)
- Permissions: Sudo/Administrator required
