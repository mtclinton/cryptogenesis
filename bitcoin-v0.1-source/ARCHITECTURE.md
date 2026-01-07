# Bitcoin v0.1 Architecture and System Design

This document explains how all the components of Bitcoin v0.1 work together to create a functioning cryptocurrency system.

## Table of Contents

1. [System Overview](#system-overview)
2. [Core Components](#core-components)
3. [File Organization and Dependencies](#file-organization-and-dependencies)
4. [System Startup Sequence](#system-startup-sequence)
5. [Data Flow](#data-flow)
6. [Key Processes](#key-processes)
7. [Global State Management](#global-state-management)
8. [Threading Model](#threading-model)

---

## System Overview

Bitcoin v0.1 is a peer-to-peer electronic cash system that operates without a central authority. The system consists of:

- **Blockchain**: A distributed ledger of all transactions
- **Transactions**: Transfers of value between addresses
- **Mining**: Process of creating new blocks and validating transactions
- **Networking**: P2P protocol for block and transaction propagation
- **Wallet**: Key management and transaction creation
- **Database**: Persistent storage using Berkeley DB

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Bitcoin Node                              │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   UI Layer   │    │  Main Logic  │    │  Network     │  │
│  │  (ui.cpp)    │◄───┤ (main.cpp)   ├───►│  (net.cpp)   │  │
│  └──────────────┘    └──────┬───────┘    └──────────────┘  │
│                              │                                │
│  ┌──────────────┐    ┌───────▼───────┐    ┌──────────────┐  │
│  │   Script     │    │   Database    │    │   Mining     │  │
│  │ (script.cpp) │    │   (db.cpp)    │    │ (main.cpp)   │  │
│  └──────────────┘    └───────────────┘    └──────────────┘  │
│                                                               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Crypto      │    │ Serialization│    │   Utilities  │  │
│  │  (key.h)     │    │(serialize.h) │    │  (util.cpp)  │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. **main.h / main.cpp** - Core Blockchain Logic

**Purpose**: The heart of Bitcoin. Manages blocks, transactions, the blockchain, and wallet operations.

**Key Classes**:
- `CTransaction` - Represents a Bitcoin transaction
- `CBlock` - Represents a block containing transactions
- `CBlockIndex` - Index entry for a block (metadata, not full block)
- `CWalletTx` - Wallet transaction (extends CTransaction with wallet-specific data)
- `CTxIn` / `CTxOut` - Transaction inputs and outputs
- `COutPoint` - Reference to a transaction output (tx hash + output index)

**Key Functions**:
- `ProcessMessage()` - Handles incoming network messages (blocks, transactions)
- `AcceptTransaction()` - Validates and adds transaction to mempool
- `AcceptBlock()` - Validates and adds block to blockchain
- `BitcoinMiner()` - Mining loop that creates new blocks
- `CreateTransaction()` - Creates a new transaction from wallet
- `SendMoney()` - Sends bitcoins to an address

**Global State** (in main.cpp):
```cpp
map<uint256, CTransaction> mapTransactions;      // Mempool: unconfirmed transactions
map<uint256, CBlockIndex*> mapBlockIndex;         // Block index (metadata)
map<uint256, CWalletTx> mapWallet;                 // Wallet transactions
map<uint256, CBlock*> mapOrphanBlocks;            // Orphan blocks (missing parent)
CBlockIndex* pindexBest;                          // Tip of best chain
int nBestHeight;                                   // Height of best chain
```

### 2. **net.h / net.cpp** - P2P Networking

**Purpose**: Handles peer-to-peer communication between Bitcoin nodes.

**Key Classes**:
- `CNode` - Represents a connection to another node
- `CAddress` - Network address (IP + port)
- `CMessageHeader` - Message header (command, size, magic bytes)
- `CInv` - Inventory item (block or transaction hash)

**Key Functions**:
- `StartNode()` - Initializes networking, starts threads
- `ConnectNode()` - Connects to a peer
- `ProcessMessages()` - Processes incoming messages from a peer
- `SendMessages()` - Sends queued messages to a peer
- `ThreadMessageHandler2()` - Thread that processes messages
- `ThreadSocketHandler2()` - Thread that handles socket I/O
- `ThreadOpenConnections2()` - Thread that opens new connections

**Message Types**:
- `version` - Initial handshake
- `addr` - Peer addresses
- `inv` - Inventory (list of blocks/tx hashes)
- `getdata` - Request for block/transaction
- `block` - Block data
- `tx` - Transaction data
- `getblocks` - Request block hashes
- `getheaders` - Request block headers

### 3. **db.h / db.cpp** - Database Layer

**Purpose**: Persistent storage using Berkeley DB.

**Key Classes**:
- `CDB` - Database wrapper class
- `CTxDB` - Transaction database
- `CBlockDB` - Block database
- `CAddrDB` - Address book database
- `CWalletDB` - Wallet database

**Stored Data**:
- Blocks (in files: `blk00000.dat`, `blk00001.dat`, ...)
- Block index (in `blkindex.dat`)
- Transactions (in `txindex.dat`)
- Wallet keys and transactions
- Address book

**Key Functions**:
- `CDB::Read()` / `CDB::Write()` - Read/write database entries
- `OpenBlockFile()` - Opens a block file
- `AppendBlockFile()` - Creates/appends to block file

### 4. **script.h / script.cpp** - Script Interpreter

**Purpose**: Executes Bitcoin scripts to validate transactions.

**Key Classes**:
- `CScript` - Bitcoin script (bytecode)
- `CScriptVM` - Script virtual machine (stack-based)

**Key Functions**:
- `EvalScript()` - Executes a script
- `VerifySignature()` - Verifies ECDSA signature
- `IsMine()` - Checks if output belongs to wallet

**Script Types**:
- **ScriptPubKey** (output script): Defines spending conditions
- **ScriptSig** (input script): Provides data to satisfy conditions

**Common Script Pattern**:
```
ScriptSig: <signature> <pubkey>
ScriptPubKey: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
```

### 5. **key.h** - Cryptography

**Purpose**: ECDSA key generation, signing, and verification.

**Key Classes**:
- `CKey` - Private/public key pair
- `CPubKey` - Public key

**Key Functions**:
- `CKey::MakeNewKey()` - Generates new key pair
- `CKey::Sign()` - Signs a hash
- `CKey::Verify()` - Verifies a signature

**Dependencies**: OpenSSL (libeay32.dll)

### 6. **serialize.h** - Serialization Framework

**Purpose**: Converts C++ objects to/from binary format for storage and network transmission.

**Key Classes**:
- `CDataStream` - Stream for serialization
- `IMPLEMENT_SERIALIZE` - Macro for implementing serialization

**Serialization Modes**:
- `SER_DISK` - For disk storage
- `SER_NETWORK` - For network transmission
- `SER_GETHASH` - For hashing

### 7. **uint256.h** - 256-bit Integers

**Purpose**: Represents 256-bit numbers (used for hashes, difficulty targets).

**Key Classes**:
- `uint256` - 256-bit unsigned integer
- `arith_uint256` - Arithmetic operations on uint256

**Usage**:
- Block hashes
- Transaction IDs
- Merkle roots
- Proof-of-work targets

### 8. **sha.cpp / sha.h** - Hashing

**Purpose**: SHA-256 and RIPEMD-160 hash functions.

**Key Functions**:
- `SHA256()` - SHA-256 hash
- `RIPEMD160()` - RIPEMD-160 hash
- `Hash()` - Double SHA-256

**Dependencies**: OpenSSL

### 9. **util.cpp / util.h** - Utilities

**Purpose**: Common utility functions.

**Key Functions**:
- `FormatMoney()` - Formats satoshis as BTC
- `ParseMoney()` - Parses BTC string to satoshis
- `GetTime()` - Current timestamp
- `error()` - Error logging
- `strprintf()` - Formatted string printing

### 10. **ui.cpp / ui.h / uibase.cpp / uibase.h** - User Interface

**Purpose**: wxWidgets-based GUI.

**Key Classes**:
- `BitcoinFrame` - Main window
- `TransactionDialog` - Send transaction dialog

**Features**:
- Wallet balance display
- Transaction history
- Send/receive interface
- Address book

### 11. **irc.cpp / irc.h** - IRC Peer Discovery

**Purpose**: Discovers peers via IRC channels (early peer discovery method).

**Key Functions**:
- `ThreadIRCSeed()` - Connects to IRC to find peers

### 12. **market.cpp / market.h** - Market/Exchange

**Purpose**: Early market functionality (not core to Bitcoin protocol).

---

## File Organization and Dependencies

### Include Hierarchy

```
headers.h (master include)
├── serialize.h
├── uint256.h
├── util.h
├── key.h
├── bignum.h
├── base58.h
├── script.h
├── db.h
├── net.h
├── irc.h
├── main.h
├── market.h
├── uibase.h
└── ui.h
```

### Source File Dependencies

**main.cpp** depends on:
- `main.h` - Core data structures
- `db.h` - Database operations
- `net.h` - Network message handling
- `script.h` - Transaction validation
- `key.h` - Cryptography
- `serialize.h` - Serialization

**net.cpp** depends on:
- `net.h` - Network structures
- `main.h` - Blocks and transactions
- `db.h` - Database

**script.cpp** depends on:
- `script.h` - Script structures
- `key.h` - Signature verification
- `main.h` - Transaction structures

---

## System Startup Sequence

### 1. Application Entry Point

**File**: `source/ui.cpp` (wxWidgets application)

```cpp
IMPLEMENT_APP(BitcoinApp)
```

The wxWidgets framework calls `BitcoinApp::OnInit()`.

### 2. Initialization Steps

1. **Load Settings** - Read configuration
2. **Initialize Database** - Open Berkeley DB environment
3. **Load Block Index** - `LoadBlockIndex()` reads `blkindex.dat`
4. **Load Wallet** - Read wallet keys and transactions from database
5. **Start Network** - `StartNode()` initializes networking:
   - Creates listening socket (port 8333)
   - Starts network threads:
     - `ThreadSocketHandler2()` - Socket I/O
     - `ThreadMessageHandler2()` - Message processing
     - `ThreadOpenConnections2()` - New connections
     - `ThreadIRCSeed()` - IRC peer discovery
6. **Start Mining Thread** (if enabled) - `ThreadBitcoinMiner()`
7. **Show UI** - Display main window

### 3. Network Initialization

**Function**: `StartNode()` in `net.cpp`

1. Initialize Winsock
2. Create listening socket
3. Bind to port 8333
4. Start network threads
5. Connect to known peers or use IRC discovery

### 4. Block Index Loading

**Function**: `LoadBlockIndex()` in `main.cpp`

1. Open `blkindex.dat` database
2. Read all `CDiskBlockIndex` entries
3. Build `mapBlockIndex` (hash → CBlockIndex*)
4. Find best chain (highest work)
5. Set `pindexBest` to tip of best chain

---

## Data Flow

### Transaction Flow

```
1. User creates transaction (UI)
   ↓
2. CreateTransaction() - Selects UTXOs, creates inputs/outputs
   ↓
3. Sign transaction with private keys
   ↓
4. AcceptTransaction() - Validates:
   - Scripts execute correctly
   - Inputs are unspent
   - Fees are sufficient
   ↓
5. Add to mapTransactions (mempool)
   ↓
6. RelayWalletTransaction() - Broadcast to peers
   ↓
7. Peers receive via ProcessMessage("tx")
   ↓
8. Miner includes in block
   ↓
9. Block is mined and broadcast
   ↓
10. Transaction confirmed (included in blockchain)
```

### Block Flow

```
1. Miner creates block (BitcoinMiner())
   - Selects transactions from mempool
   - Creates coinbase transaction
   - Builds merkle tree
   - Finds proof-of-work
   ↓
2. AcceptBlock() - Validates:
   - Block hash meets difficulty
   - All transactions are valid
   - Merkle root is correct
   - Previous block exists
   ↓
3. Add to mapBlockIndex
   ↓
4. Write to disk (blk*.dat file)
   ↓
5. Update best chain if this block extends it
   ↓
6. RelayBlock() - Broadcast to peers
   ↓
7. Peers receive via ProcessMessage("block")
   ↓
8. Peers validate and add to their blockchain
```

### Network Message Flow

```
Peer A                          Peer B
  │                               │
  │─── version ──────────────────►│
  │                               │
  │◄── version ───────────────────│
  │                               │
  │─── getblocks ────────────────►│
  │                               │
  │◄── inv (block hashes) ────────│
  │                               │
  │─── getdata (block) ──────────►│
  │                               │
  │◄── block ──────────────────────│
  │                               │
```

**Thread Architecture**:

```
Main Thread
├── UI Event Loop
└── Network Threads
    ├── ThreadSocketHandler2() - Socket I/O
    ├── ThreadMessageHandler2() - Process messages
    ├── ThreadOpenConnections2() - New connections
    └── ThreadBitcoinMiner() - Mining (if enabled)
```

---

## Key Processes

### 1. Transaction Validation

**Function**: `CTransaction::AcceptTransaction()` in `main.cpp`

**Steps**:
1. Check if transaction already exists
2. Validate basic structure (inputs, outputs)
3. For each input:
   - Find previous transaction output
   - Execute script (ScriptSig + ScriptPubKey)
   - Verify signature
   - Check output is unspent
4. Calculate fees
5. Add to mempool (`mapTransactions`)

### 2. Block Validation

**Function**: `CBlock::AcceptBlock()` in `main.cpp`

**Steps**:
1. Check block hash meets difficulty target
2. Verify previous block exists
3. Validate all transactions:
   - Call `AcceptTransaction()` for each
   - Check coinbase maturity
4. Verify merkle root
5. Check block size limits
6. Add to block index
7. Write to disk
8. Update best chain if needed

### 3. Mining Process

**Function**: `BitcoinMiner()` in `main.cpp`

**Steps**:
1. Create coinbase transaction (block reward)
2. Select transactions from mempool
3. Build block:
   - Set previous block hash
   - Build merkle tree
   - Set timestamp, version, bits
4. Mine (proof-of-work):
   - Increment nonce
   - Hash block header
   - Check if hash < target
   - Repeat until found
5. Submit block: `AcceptBlock()`

### 4. Peer Connection

**Function**: `ThreadOpenConnections2()` in `net.cpp`

**Steps**:
1. Get list of peer addresses (from IRC, database, or hardcoded)
2. For each address:
   - Connect socket
   - Send `version` message
   - Wait for `version` response
   - Add to `vNodes` list
3. Request blocks: `getblocks` message

### 5. Message Processing

**Function**: `ProcessMessage()` in `main.cpp`

**Handles**:
- `version` - Peer handshake
- `addr` - Peer addresses
- `inv` - Inventory (block/tx hashes)
- `getdata` - Request for data
- `block` - Block data → `AcceptBlock()`
- `tx` - Transaction data → `AcceptTransaction()`
- `getblocks` - Request block hashes
- `getheaders` - Request block headers

---

## Global State Management

### Critical Sections (Locks)

Bitcoin uses critical sections (mutexes) to protect shared data:

- `cs_main` - Main critical section (blocks, transactions)
- `cs_mapTransactions` - Mempool
- `cs_mapWallet` - Wallet
- `cs_mapKeys` - Private keys
- `cs_vNodes` - Network connections
- `cs_mapAddresses` - Peer addresses

### Key Global Variables

**In main.cpp**:
```cpp
map<uint256, CTransaction> mapTransactions;      // Mempool
map<uint256, CBlockIndex*> mapBlockIndex;        // Block index
map<uint256, CWalletTx> mapWallet;                // Wallet
CBlockIndex* pindexBest;                          // Best chain tip
int nBestHeight;                                  // Chain height
```

**In net.cpp**:
```cpp
vector<CNode*> vNodes;                            // Connected peers
map<vector<unsigned char>, CAddress> mapAddresses; // Known addresses
```

---

## Threading Model

Bitcoin v0.1 uses multiple threads:

1. **Main Thread** - UI event loop
2. **ThreadSocketHandler2** - Handles socket I/O (select/poll)
3. **ThreadMessageHandler2** - Processes incoming messages
4. **ThreadOpenConnections2** - Opens new peer connections
5. **ThreadIRCSeed** - IRC peer discovery
6. **ThreadBitcoinMiner** - Mining (if enabled)

### Thread Communication

- **Critical sections** protect shared data
- **Message queues** (`vRecv`, `vSend` in `CNode`) for network messages
- **Event signaling** for thread coordination

---

## Summary

Bitcoin v0.1 is a complex system with multiple interacting components:

1. **main.cpp** orchestrates everything - blocks, transactions, wallet
2. **net.cpp** handles P2P communication
3. **db.cpp** provides persistence
4. **script.cpp** validates transactions
5. **key.h** provides cryptography
6. **serialize.h** handles data encoding

The system works by:
- Nodes connect via P2P network
- Transactions are created, validated, and broadcast
- Miners create blocks containing transactions
- Blocks are validated and added to blockchain
- All state is persisted to Berkeley DB

This architecture enables a decentralized, trustless payment system without a central authority.

