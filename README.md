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

## Running Locally with Multiple Nodes

For detailed instructions on running multiple nodes locally (including Docker setup), see:

- **[RUNNING_LOCALLY.md](RUNNING_LOCALLY.md)** - Complete guide for local multi-node setup
- **[scripts/](scripts/)** - Helper scripts for network management

### Quick Docker Start
```bash
# Test setup
./scripts/test-docker-setup.sh

# Start 3-node network (1 mining, 2 relay nodes)
docker-compose up -d

# Monitor network
./scripts/monitor-network.sh

# Run integration tests
./scripts/run-integration-tests.sh
```

**Note:** Uses private network mode with custom parameters - completely isolated from Bitcoin mainnet.

## Status

Most of the core protocol is implemented - transactions, blocks, script evaluation, networking, mempool, chain storage, UTXO management, and wallet functionality. The genesis block hash matches, so serialization is correct.

This is for learning, not production. Missing pieces: database layer (everything's in-memory), full mining, and some edge cases.

## License

MIT/X11, same as the original Bitcoin code.
