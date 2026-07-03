# Welcome to the Free Communicate！

# HelloFreecom

1.**Discussion**
**Peer to peer text chat function. Breaks messages into encrypted fragments for transmission, assembles complete content on the receiver’s end. Hit Enter to dispatch messages directly.**

2. **Filesharing**
**Encrypted file delivery tool. Splits files into tiny encrypted chunks, distributes chunks alongside dummy noise files following current security rules.**

3. **Security Levels**
**Global policy. Adjusts encryption strength, network camouflage, storage rules and anti-tracking tactics for the whole program in real time.**

4. **Storage**
**Controls encrypted fragment file management. Handles random directory placement, metadata tampering, disk secure overwriting and mixing of real & decoy files.**

5. **Database**
**Works only with in-memory temporary indexes. Never writes logs to local disk. Erases all hash index data instantly once the session closes.**

6. **Friends**
**Peer node manager. Stores one-time handshake access tokens and virtual IP mappings, maintains P2P connection status and automatic reconnection logic.**

7. **Statistics**
**P2P Network status online and other status**

# Security Levels Mangement

1.**None**
    Debug only. Plaintext transfer, real IP used, permanent local logs, no encryption or obfuscation.

--Only for local debugging. Never use on public networks, all data is fully exposed

2. **Low**
    Basic encryption with fixed global key. Few large ordered fragments, static virtual IP, auto clear logs in   days, speed priority.

--Suitable for trusted local LAN. Anonymity is weak, traffic can still be easily tracked.

3. **Normal**
    Session-only AES key destroyed after exit. Dozens of randomized fragments, periodic IP rotation, in-      memory indexes only, balanced privacy & speed.

--Best for daily private chat. Balanced performance and privacy for regular use

4. **High**
    Unique key per message, hundreds of fragments mixed with decoys. Frequent IP & port switching,         modified file metadata, strict system access limits.

--Notice bandwidth consumption rises. Good for sensitive communication scenarios

# 5.Maximum
# One-time unique key for every fragment. Thousands of scattered micro chunks + equal decoys. IP changes per packet, non-stop noise traffic, full memory & disk data erasure on exit, zero residual traces.

--**High resource & bandwidth cost. No data recoverable after session termination**

?. **Freedom Comimum**
# The Last Security modes. Fully peer‑to‑peer with no third parties, this system uses a single offline 64‑byte handshake token and resists signal intelligence, deep inspection, and kernel‑level forensics. It combines one‑time pads with post‑quantum crypto, keeping each 128‑byte fragment’s 256‑bit key solely in CPU registers for under 80 ns with no contiguous memory footprint. Fragments (up to 65,536) are interleaved with 1:1.2 decoys across 12 hashed layers, with no persisted indices and ordering resolved only in cache. Transmission runs at raw Ethernet, bypassing the kernel stack and firewalls, with randomized headers making traffic indistinguishable from physical noise. The runtime is hidden from the OS, locks memory to physical addresses, avoids swap/dumps, and keeps data in L1/L2 cache. Any breach triggers full zeroization within 12 ms, 42 overwrites, and 128 renames, making recovery below 1×10⁻¹⁸ while supporting total cryptographic deniability

**Also, Freedom Comimum mode disabled INJECT_EVENTS and /dev/xxxx storage, At this stage We disabled some dangerous permission either.**# Freedom
Communicate Script
