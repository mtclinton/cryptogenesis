# Bitcoin v0.1 in Python

A Python 3 re-implementation of the original Bitcoin protocol from 2009. I've been translating Satoshi's original C++ code to Python to better understand how Bitcoin works under the hood.

## What's Inside

This implementation covers the core Bitcoin structures and operations:

- **Data types**: 256-bit and 160-bit integers for hashes and addresses
- **Transactions**: Inputs, outputs, and the transaction structure
- **Scripts**: The Bitcoin scripting system (basic structure)
- **Blocks**: Block headers, merkle trees, and validation
- **Crypto**: SHA256, RIPEMD160, and ECDSA key operations
- **Serialization**: The network format for sending data around

The genesis block hash matches the original, so the core serialization and hashing logic is correct.

## Getting Started

You'll need Python 3.6 or newer. Install the one dependency:

```bash
pip install ecdsa
```

Then run the main script:

```bash
python3 main.py
```

This creates the genesis block, generates a test key, builds a transaction, and validates everything. If you see the genesis block hash match, you're good to go.

## Project Structure

- `uint256.py` - Big integer types for hashes
- `serialize.py` - Converting data to/from the network format
- `crypto.py` - Hashing and ECDSA operations
- `transaction.py` - Transactions, inputs, outputs, and scripts
- `block.py` - Blocks and blockchain logic
- `main.py` - Entry point with some basic tests

## What Works

The core protocol structures are implemented:
- Transaction creation and validation
- Block structure with merkle trees
- Script system (the opcodes are there, but full execution isn't implemented)
- Genesis block that matches the original
- Proof of work target calculation
- All the serialization formats

## What's Missing

This is an educational project, not a full Bitcoin node. I've focused on understanding the protocol structures rather than building a complete system. Missing pieces include:

- P2P networking (no talking to other nodes)
- Full wallet functionality (no database, just in-memory)
- Complete script interpreter (structure is there, but execution is simplified)
- Mining (proof-of-work calculation exists, but no actual mining)
- Database layer (everything is in-memory)

## Differences from the Original

- Written in Python instead of C++ (obviously)
- Uses Python's `ecdsa` library instead of OpenSSL
- Script execution is simplified - the structure is there but not the full interpreter
- No database - everything lives in memory
- No networking code

The serialization formats match though, so data structures are compatible.

## Why This Exists

I wanted to understand Bitcoin's protocol by implementing it myself. Reading the original C++ code is one thing, but actually writing it helps you see all the details. The original Bitcoin v0.1 code is in the `Bitcoin-v0.1` directory if you want to compare.

This is for learning, not for running a real Bitcoin node. If you need that, use Bitcoin Core.

## License

Same as the original Bitcoin code - MIT/X11 license. The original copyright notice is preserved in the source files.
