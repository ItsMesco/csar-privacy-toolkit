# CSAR Privacy Toolkit: Zero-Knowledge Client-Side Scanning

A cryptographically secure, privacy-preserving Client-Side Scanning (CSS) architecture. This project evaluates different cryptographic paradigms (Zero-Knowledge Proofs and Homomorphic Encryption) to detect illegal content on end-user devices without exposing personal data, original media, or plaintext hashes to service providers or authorities.

## 🏗️ Architecture Overview

The system strictly separates responsibilities to ensure *Privacy by Design* and *Tamper Evidence*:
1. **Client (Mobile/Desktop):** Extracts PDQ perceptual hashes, runs cryptographic protocols (ZKP/PHE) to evaluate Hamming distance proximity, and encrypts the user's identity via RSA-OAEP.
2. **Privacy Ledger:** A local, SQLite-based append-only database. It acts as the leaves of a Merkle Tree to guarantee mathematical accountability.
3. **Provider (Backend):** Verifies the cryptographic validity and handles the Remote Commitment of the Merkle Root. It is cryptographically blind to the user's identity.
4. **Authority:** Holds the RSA private key to reveal identities strictly upon valid mathematical proofs of illicit content.

## 🔬 Cryptographic Strategies

This toolkit evaluates and compares different privacy-preserving computation paradigms:
* **Zero-Knowledge Proofs (ZKP):** Client-side proof generation using Groth16 over BN254. High client computation overhead, minimal server overhead.
* **Partially Homomorphic Encryption (PHE) - *[In Progress]*:** Encrypted computation delegated to the server (e.g., Paillier cryptosystem). Minimal client overhead, higher network and server computation overhead.

## 🚀 Features Implemented

* **Real Math Execution:** Full end-to-end ZKP generation using `arkworks`.
* **Perceptual Hashing:** Integrates PDQ hashing for robust image analysis.
* **Tamper-Evident Ledger:** Local auditing CLI to reconstruct and verify the Merkle Tree root.
* **Telemetry & Metrics:** Built-in `MetricsCollector` to track latency, RSS (Resident Set Size) memory delta, and database storage impact.

## 🛠️ Usage

### Run the End-to-End Pipeline (Client)
To simulate a full scan, ZKP generation, identity encryption, and local ledger append:
```bash
cargo run --release --bin frontend