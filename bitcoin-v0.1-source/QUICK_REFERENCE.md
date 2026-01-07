# Bitcoin v0.1 Quick Reference

A quick reference guide for understanding the Bitcoin v0.1 codebase.

## File Purpose Summary

| File | Purpose | Key Classes/Functions |
|-----|---------|---------------------|
| **main.h/main.cpp** | Core blockchain logic | `CTransaction`, `CBlock`, `CBlockIndex`, `AcceptTransaction()`, `BitcoinMiner()` |
| **net.h/net.cpp** | P2P networking | `CNode`, `ProcessMessage()`, `SendMessages()`, `StartNode()` |
| **db.h/db.cpp** | Database layer | `CDB`, `CTxDB`, `CBlockDB`, `OpenBlockFile()` |
| **script.h/script.cpp** | Script interpreter | `CScript`, `EvalScript()`, `VerifySignature()` |
| **key.h** | Cryptography | `CKey`, `CPubKey`, `Sign()`, `Verify()` |
| **serialize.h** | Serialization | `CDataStream`, `IMPLEMENT_SERIALIZE` |
| **uint256.h** | 256-bit integers | `uint256` (for hashes) |
| **sha.cpp/sha.h** | Hashing | `SHA256()`, `RIPEMD160()`, `Hash()` |
| **util.cpp/util.h** | Utilities | `FormatMoney()`, `GetTime()`, `error()` |
| **ui.cpp/ui.h** | GUI | `BitcoinFrame`, transaction dialogs |
| **irc.cpp/irc.h** | IRC peer discovery | `ThreadIRCSeed()` |

## Core Data Structures

### Transaction
```cpp
CTransaction
├── vector<CTxIn> vin      // Inputs (references to previous outputs)
├── vector<CTxOut> vout     // Outputs (amount + script)
└── uint256 GetHash()      // Transaction ID
```

### Block
```cpp
CBlock
├── uint256 prev_block_hash
├── uint256 merkle_root
├── uint32 version
├── uint32 time
├── uint32 bits            // Difficulty target
├── uint32 nonce
└── vector<CTransaction> transactions
```

### Block Index (Metadata)
```cpp
CBlockIndex
├── uint256 block_hash
├── uint256 prev
├── int height
├── uint256 merkle_root
└── uint64 nChainWork     // Cumulative proof-of-work
```

## Key Functions

### Transaction Processing
- `AcceptTransaction(tx)` - Validates and adds to mempool
- `CreateTransaction(script, value, tx)` - Creates new transaction
- `SendMoney(script, value, tx)` - Sends bitcoins

### Block Processing
- `AcceptBlock(block)` - Validates and adds to blockchain
- `LoadBlockIndex()` - Loads block index from database
- `BitcoinMiner()` - Mining loop

### Network
- `StartNode()` - Initializes networking
- `ProcessMessage(node, command, data)` - Handles incoming messages
- `SendMessages(node)` - Sends queued messages
- `ConnectNode(address)` - Connects to peer

### Script
- `EvalScript(script)` - Executes Bitcoin script
- `VerifySignature(sig, pubkey, hash)` - Verifies ECDSA signature
- `IsMine(script)` - Checks if output belongs to wallet

## Message Types

| Command | Purpose | Direction |
|---------|---------|-----------|
| `version` | Initial handshake | Bidirectional |
| `addr` | Peer addresses | Bidirectional |
| `inv` | Inventory (block/tx hashes) | Bidirectional |
| `getdata` | Request block/tx | Request |
| `block` | Block data | Response |
| `tx` | Transaction data | Response |
| `getblocks` | Request block hashes | Request |
| `getheaders` | Request block headers | Request |

## Global State Maps

```cpp
// Mempool (unconfirmed transactions)
map<uint256, CTransaction> mapTransactions;

// Block index (metadata for all blocks)
map<uint256, CBlockIndex*> mapBlockIndex;

// Wallet transactions
map<uint256, CWalletTx> mapWallet;

// Private keys (pubkey -> privkey)
map<vector<unsigned char>, CPrivKey> mapKeys;

// Connected peers
vector<CNode*> vNodes;

// Best chain
CBlockIndex* pindexBest;
int nBestHeight;
```

## Database Files

| File | Purpose |
|------|---------|
| `blk*.dat` | Block data (blk00000.dat, blk00001.dat, ...) |
| `blkindex.dat` | Block index (metadata) |
| `txindex.dat` | Transaction index |
| `wallet.dat` | Wallet keys and transactions |
| `addr.dat` | Address book |

## Script Execution

Bitcoin uses a stack-based scripting language:

```
Input Script (ScriptSig):  <signature> <pubkey>
Output Script (ScriptPubKey):  OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG

Execution:
1. Push signature and pubkey onto stack
2. Execute ScriptPubKey:
   - OP_DUP: Duplicate pubkey
   - OP_HASH160: Hash pubkey → pubkeyhash
   - Push <pubkeyhash> from script
   - OP_EQUALVERIFY: Verify hashes match
   - OP_CHECKSIG: Verify signature
3. If stack has true, transaction is valid
```

## Mining Process

1. Create coinbase transaction (block reward)
2. Select transactions from mempool
3. Build block header:
   - Previous block hash
   - Merkle root of transactions
   - Timestamp, version, bits (difficulty)
4. Mine (proof-of-work):
   - Increment nonce
   - Hash block header (SHA256²)
   - Check if hash < target
   - Repeat until found
5. Broadcast block to network

## Transaction Lifecycle

1. **Creation**: User creates transaction via UI
2. **Signing**: Transaction signed with private key
3. **Validation**: `AcceptTransaction()` validates:
   - Scripts execute correctly
   - Inputs are unspent
   - Fees sufficient
4. **Mempool**: Added to `mapTransactions`
5. **Broadcast**: Sent to connected peers
6. **Mining**: Miner includes in block
7. **Confirmation**: Block added to blockchain
8. **Spent**: Inputs marked as spent in UTXO set

## Network Protocol Flow

```
1. Connect to peer (TCP port 8333)
2. Send 'version' message
3. Receive 'version' response
4. Send 'getblocks' (request block hashes)
5. Receive 'inv' (inventory of blocks)
6. Send 'getdata' (request specific blocks)
7. Receive 'block' messages
8. Validate and add blocks to blockchain
9. Continue syncing...
```

## Critical Sections (Locks)

Protect shared data from race conditions:

- `cs_main` - Main lock (blocks, transactions)
- `cs_mapTransactions` - Mempool
- `cs_mapWallet` - Wallet
- `cs_mapKeys` - Private keys
- `cs_vNodes` - Network connections

## Threads

- **Main Thread**: UI event loop
- **ThreadSocketHandler2**: Socket I/O
- **ThreadMessageHandler2**: Message processing
- **ThreadOpenConnections2**: New connections
- **ThreadIRCSeed**: IRC peer discovery
- **ThreadBitcoinMiner**: Mining (if enabled)

## Constants

```cpp
COIN = 100000000              // 1 BTC in satoshis
COINBASE_MATURITY = 100       // Blocks until coinbase spendable
DEFAULT_PORT = 8333           // Bitcoin P2P port
MAX_SIZE = 0x02000000         // 32 MB max block size
```

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) - Detailed architecture documentation
- [README.md](README.md) - Directory structure and overview

