# Obscell Wallet: A Privacy-Preserving TUI Wallet for CKB

I'm excited to share **obscell-wallet**, a terminal-based wallet for managing privacy tokens on Nervos CKB. This wallet implements stealth addresses and confidential transactions (CT), allowing users to send and receive tokens with hidden amounts and unlinkable addresses.

## Background & Acknowledgments

First, I want to give credit to the original author **Rea-Don-Lycn** who came up with the [obscell](https://github.com/Rea-Don-Lycn/obscell) concept - combining stealth addresses with confidential transactions on CKB. The idea of using Pedersen commitments and Bulletproofs range proofs for hiding token amounts while maintaining verifiability was brilliant.

However, after the initial stealth lock implementation, the project seemed to stall with the CT (Confidential Transaction) components marked as "work in progress." Rather than let this promising idea remain incomplete, I decided to pick it up and finish the implementation - with a twist.

## Built with AI Coding Agents

The remaining CT implementation (ct-info-type, ct-token-type scripts, and this wallet) was completed using **AI coding agents**. This was an interesting experiment in AI-assisted development for blockchain/cryptographic code. The agents helped with:

- Implementing Bulletproofs range proof generation and verification
- Building the confidential token minting and transfer logic
- Creating the TUI wallet interface with ratatui
- Writing comprehensive tests including integration tests with a devnet

## Features

- **Stealth Addresses**: Recipients get one-time addresses for each transaction, making payments unlinkable
- **Confidential Amounts**: Token amounts are hidden using Pedersen commitments
- **Range Proofs**: Bulletproofs ensure amounts are valid without revealing them
- **HD Wallet**: BIP39/BIP32 compatible key derivation
- **TUI Interface**: Clean terminal UI built with ratatui
- **Multi-network**: Supports mainnet, testnet, and devnet

## Technical Details

The wallet works with three on-chain scripts:
1. **Stealth Lock** - Validates stealth address ownership using ECDH
2. **CT Info Type** - Manages token issuance and minting with commitment verification
3. **CT Token Type** - Validates confidential transfers with range proof verification

Cryptographic primitives used:
- secp256k1 for stealth address ECDH
- curve25519-dalek/Ristretto for Pedersen commitments
- Bulletproofs for zero-knowledge range proofs

## Links

- Wallet: https://github.com/quake/obscell-wallet
- Smart Contracts: https://github.com/quake/obscell (forked from Rea-Don-Lycn/obscell)

Feedback and contributions welcome!
