Demo link -> https://youtube.com/shorts/buPG5cAWfGQ
Ventus: Human Centric Media Authenticity via ZKPs

Overview:
Ventus is a privacy preserving authenticity protocol that proves a piece of digital media was captured by a real person on a trusted device, without revealing identity. Instead of detecting fakes, it proves what’s real.

Core Architecture:

Client (Mobile):
- Media signed using Secure Enclave (iOS) or attested hardware key (Android)
- Signature + metadata (timestamp, ID, etc.) included in ZK proof (Proof A)
- Proof A also shows key belongs to a local Merkle subtree
- All proving and verification is done on-device

Server (Verifier):
- Confirms subtree is included in Global Merkle Super Tree (Proof B)
- Recursively combines Proof A + Proof B into final Proof C
- Proof C = verifiable, portable, and identity-preserving

Why Recursive ZKPs?
- Enables parallelism + batching
- Keeps proofs lightweight and scalable

Verification & Storage:
- Proof C can be verified online, via API, or anchored on chain
- Merkle roots periodically published on chain for trust

Device Trust:
- iOS: Secure Enclave w/ Face ID (no public certs)
- Android: Hardware-backed keys with full attestation certs
- Future: Apple SE attestation support

Strategic Roadmap:
1.  iOS ZK demo: Face ID -> Sign -> Proof  
2.  Android demo with real attestation
3.  Server-side recursive prover
4.  Anchor roots or proofs on-chain
5.  Partner with journalists and news media
6.  Apple SE attestation partnership
7.  Standardize Ventus proof format

Progress:
- Swift iOS app working: Take photo → Face ID → Sign → ZK proof (via swoir)
- Placeholder circuit complete; Noir circuit in development
- Recursive proof design established
- Early feedback loop with Aztec (Josh)
- Addressing edge cases like AI-generated image abuse with endorsement layers

Conclusion:
Ventus is not just a deepfake filter it’s a new trust layer for digital media.

By proving realness at the time of capture, we bypass the arms race of detection and create a new paradigm for truth online.

— Omar Mohamed
