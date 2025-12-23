# Viewing Bitcoin Node Logs

## View logs from a specific node

```bash
# View logs from node1 (follow mode - shows new lines as they appear)
docker logs -f bitcoin-node-1

# View logs from node2
docker logs -f bitcoin-node-2

# View logs from any node (replace N with 1-10)
docker logs -f bitcoin-node-N
```

## View logs using docker-compose

```bash
# View logs from node1
docker-compose logs -f node1

# View logs from multiple nodes
docker-compose logs -f node1 node2 node3

# View logs from all nodes
docker-compose logs -f
```

## View last N lines

```bash
# View last 100 lines from node1
docker logs --tail 100 bitcoin-node-1

# View last 50 lines and follow
docker logs --tail 50 -f bitcoin-node-1
```

## View logs without following

```bash
# View all logs from node1 (one-time output)
docker logs bitcoin-node-1

# View logs with timestamps
docker logs -t bitcoin-node-1
```

## Useful log viewing examples

```bash
# Watch node1 in real-time
docker logs -f bitcoin-node-1

# Watch all nodes at once
docker-compose logs -f

# View last 50 lines of node1, then follow
docker logs --tail 50 -f bitcoin-node-1

# View logs with timestamps
docker logs -t -f bitcoin-node-1
```

## Filter logs

```bash
# View logs and grep for specific patterns
docker logs bitcoin-node-1 | grep "Height:"
docker logs bitcoin-node-1 | grep "Transaction"
docker logs bitcoin-node-1 | grep "ERROR"
docker logs bitcoin-node-1 | grep "Connected"
```

## Container names

- bitcoin-node-1 through bitcoin-node-10
- Or use: node1, node2, etc. with docker-compose
