# Bitcoin v0.1 in Python

Python re-implementation of the original Bitcoin protocol from 2009. I'm translating Satoshi's C++ code to understand how Bitcoin actually works.

## What is in it

Core Bitcoin structures and operations:
- Transactions, blocks, scripts
- Crypto (SHA256, RIPEMD160, ECDSA)
- Serialization formats
- Genesis block (hash matches the original)

## Quick Start

```bash
pip install ecdsa
python3 main.py
```

## Running Multiple Nodes with Docker

Run 10 nodes in a Docker network for testing:

```bash
# Build and start all nodes
docker-compose up --build

# View logs from a specific node
docker-compose logs -f node1

# Stop all nodes
docker-compose down

# Restart a specific node
docker-compose restart node1
```

**Note:** This implementation uses in-memory storage. All blockchain data, transactions, and wallet state are lost when containers stop/restart. Each node starts fresh with the genesis block and syncs from peers.

## Status

Most of the core protocol is implemented - transactions, blocks, script evaluation, networking, mempool, chain storage, UTXO management, and wallet functionality. The genesis block hash matches, so serialization is correct.

This is for learning, not production. Missing pieces: database layer (everything's in-memory), full mining, and some edge cases.

## License

MIT/X11, same as the original Bitcoin code.
