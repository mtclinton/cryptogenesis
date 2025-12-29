# Bitcoin v0.1 Original Source Code

This directory contains the original Bitcoin v0.1 C++ source code from 2009, organized for easy study and reference.

## Directory Structure

- **`source/`** - C++ implementation files (.cpp)
  - `main.cpp` - Main entry point and application logic
  - `db.cpp` - Database layer (Berkeley DB)
  - `net.cpp` - Network/P2P communication
  - `script.cpp` - Bitcoin script interpreter
  - `sha.cpp` - SHA-256 hashing implementation
  - `util.cpp` - Utility functions
  - `irc.cpp` - IRC peer discovery
  - `market.cpp` - Market/exchange functionality
  - `ui.cpp` - User interface
  - `uibase.cpp` - UI base classes

- **`headers/`** - C++ header files (.h)
  - `main.h` - Main application headers
  - `db.h` - Database interface
  - `net.h` - Network protocol definitions
  - `script.h` - Script opcodes and structures
  - `sha.h` - SHA-256 header
  - `util.h` - Utility function declarations
  - `key.h` - Cryptographic key management
  - `uint256.h` - 256-bit integer implementation
  - `bignum.h` - Big number arithmetic
  - `base58.h` - Base58 encoding/decoding
  - `serialize.h` - Serialization framework
  - `headers.h` - Common includes
  - `irc.h`, `market.h`, `ui.h`, `uibase.h` - Feature headers

- **`resources/`** - UI resources and assets
  - `rc/` - Windows resource files (icons, bitmaps)

- **`docs/`** - Documentation
  - `readme.txt` - Original build instructions and dependencies
  - `license.txt` - MIT/X11 license

- **`build/`** - Build configuration files
  - `makefile` - Unix/MinGW build configuration
  - `makefile.vc` - Visual C++ build configuration
  - `ui.rc` - Windows resource script
  - `uiproject.fbp` - wxWidgets UI project file

## About This Code

This is the original Bitcoin v0.1 source code released by Satoshi Nakamoto in 2009. It represents the first public implementation of the Bitcoin protocol.

**Copyright:** (c) 2009 Satoshi Nakamoto
**License:** MIT/X11 software license

## Key Components

1. **Transactions & Blocks** - Core blockchain data structures
2. **Script System** - Stack-based scripting language for transaction validation
3. **Cryptography** - ECDSA signatures, SHA-256 hashing, RIPEMD-160
4. **Networking** - P2P protocol for block and transaction propagation
5. **Database** - Berkeley DB for blockchain storage
6. **Wallet** - Key management and transaction creation

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Comprehensive guide explaining how all components work together, system startup, data flow, and key processes
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Quick reference guide with file purposes, key functions, and data structures

## Study Notes

This codebase is the reference implementation for the Python translation in the `cryptogenesis/` directory. Key files to study:

- `main.cpp` - Application entry point and transaction/block handling
- `script.cpp` - Script evaluation logic (critical for understanding transaction validation)
- `net.cpp` - P2P networking protocol
- `db.cpp` - Blockchain storage and retrieval
- `util.cpp` - Serialization and utility functions

**Start with**: Read [ARCHITECTURE.md](ARCHITECTURE.md) for a complete understanding of how the system works, then use [QUICK_REFERENCE.md](QUICK_REFERENCE.md) as a cheat sheet while reading the code.

## Dependencies (for building)

- wxWidgets (GUI framework)
- OpenSSL (cryptographic functions)
- Berkeley DB (database)
- Boost (C++ libraries)

See `docs/readme.txt` for detailed build instructions.
