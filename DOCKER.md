# Running Bitcoin Nodes with Docker

This setup runs 10 Bitcoin nodes in a Docker network for testing and learning.

## Quick Start

```bash
# Build and start all 10 nodes
docker-compose up --build

# View logs from all nodes
docker-compose logs -f

# View logs from a specific node
docker-compose logs -f node1

# Stop all nodes
docker-compose down

# Restart a specific node
docker-compose restart node1
```

## Architecture

- **10 nodes** running in separate containers
- **Docker bridge network** (172.20.0.0/16) for node communication
- **Port mapping**: Each node listens on port 8333 internally, mapped to ports 8333-8342 on host
- **Peer connections**: Nodes connect to each other using Docker service names

## Node Configuration

Each node:
- Starts with the genesis block
- Connects to 3-4 peer nodes
- Automatically starts mining
- Creates test transactions every 30 seconds
- Syncs blockchain from peers

## Important Notes

⚠️ **In-Memory Storage**: This implementation uses in-memory storage only. All data (blockchain, transactions, wallet) is lost when containers stop/restart.

- Each container restart = fresh start with only genesis block
- Nodes will re-sync from peers after restart
- No persistence across container restarts
- Good for testing consensus and networking
- Not suitable for long-term state preservation

## Network Topology

```
node1 ──┬── node2 ──┬── node3
        │           │
        ├── node4   ├── node8
        │           │
        └── node5   └── node9
             │           │
             ├── node6   └── node10
             │
             └── node7
```

## Troubleshooting

**Nodes not connecting?**
- Wait a few seconds after startup for network initialization
- Check logs: `docker-compose logs node1`
- Verify Docker network: `docker network inspect cryptogenesis_bitcoin-network`

**Port conflicts?**
- Change port mappings in `docker-compose.yml` if ports 8333-8342 are in use

**High CPU usage?**
- All nodes mine simultaneously - this is expected
- Stop mining on specific nodes by modifying `run_node.py`

## Customization

Edit `run_node.py` to:
- Change transaction creation frequency (default: 30 seconds)
- Modify mining behavior
- Add custom transaction logic
- Adjust peer connections

Edit `docker-compose.yml` to:
- Change number of nodes
- Modify peer connections
- Adjust port mappings
- Change network configuration
