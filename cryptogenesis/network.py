"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Network functionality for Bitcoin protocol
"""

import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

from cryptogenesis.serialize import SER_NETWORK, DataStream
from cryptogenesis.transaction import Transaction
from cryptogenesis.uint256 import uint256

# Message start bytes (magic bytes)
MESSAGE_START = bytes([0xF9, 0xBE, 0xB4, 0xD9])

# Default port
DEFAULT_PORT = 8333

# Node services
NODE_NETWORK = 1 << 0

# Message types
MSG_TX = 1
MSG_BLOCK = 2
MSG_REVIEW = 3
MSG_PRODUCT = 4
MSG_TABLE = 5

TYPE_NAMES = {
    0: "ERROR",
    MSG_TX: "tx",
    MSG_BLOCK: "block",
    MSG_REVIEW: "review",
    MSG_PRODUCT: "product",
    MSG_TABLE: "table",
}


class MessageHeader:
    """Bitcoin message header"""

    COMMAND_SIZE = 12

    def __init__(self, command: str = "", message_size: int = 0):
        self.message_start = MESSAGE_START
        self.command = command.ljust(self.COMMAND_SIZE, "\x00")[: self.COMMAND_SIZE]
        self.message_size = message_size

    def serialize(self, stream: DataStream, n_type: int = 0, n_version: int = 101):
        """Serialize message header"""
        stream.write(self.message_start)
        stream.write(self.command.encode("ascii"))
        stream.write(struct.pack("<I", self.message_size))

    def unserialize(self, stream: DataStream, n_type: int = 0, n_version: int = 101):
        """Unserialize message header"""
        self.message_start = stream.read(4)
        command_bytes = stream.read(self.COMMAND_SIZE)
        self.command = command_bytes.rstrip(b"\x00").decode("ascii", errors="ignore")
        self.message_size = struct.unpack("<I", stream.read(4))[0]

    def get_command(self) -> str:
        """Get command string"""
        return self.command.rstrip("\x00")

    def is_valid(self) -> bool:
        """Check if header is valid"""
        if self.message_start != MESSAGE_START:
            return False

        # Check command string
        for c in self.command:
            if c == "\x00":
                break
            if c < " " or ord(c) > 0x7E:
                return False

        # Check message size
        if self.message_size > 0x10000000:  # 256MB
            return False

        return True


class Address:
    """Network address"""

    IPv4_PREFIX = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF])

    def __init__(self, ip: int = 0, port: int = DEFAULT_PORT, services: int = 0):
        self.services = services
        self.reserved = self.IPv4_PREFIX
        self.ip = ip
        self.port = port
        from cryptogenesis.util import get_adjusted_time

        self.time = get_adjusted_time()
        self.last_failed = 0

    @classmethod
    def from_string(cls, addr_str: str, services: int = 0):
        """Create address from string like '127.0.0.1:8333'"""
        if ":" in addr_str:
            ip_str, port_str = addr_str.rsplit(":", 1)
            port = int(port_str)
        else:
            ip_str = addr_str
            port = DEFAULT_PORT

        try:
            ip = struct.unpack(">I", socket.inet_aton(ip_str))[0]
        except Exception:
            ip = 0

        return cls(ip, port, services)

    def serialize(self, stream: DataStream, n_type: int = 0, n_version: int = 101):
        """Serialize address"""
        if n_type & 0x02:  # SER_DISK
            stream.write(struct.pack("<I", n_version))
            stream.write(struct.pack("<I", self.time))
        stream.write(struct.pack("<Q", self.services))
        stream.write(self.reserved)
        stream.write(struct.pack(">I", self.ip))  # Network byte order
        stream.write(struct.pack(">H", self.port))  # Network byte order

    def unserialize(self, stream: DataStream, n_type: int = 0, n_version: int = 101):
        """Unserialize address"""
        if n_type & 0x02:  # SER_DISK
            struct.unpack("<I", stream.read(4))[0]  # Read and discard version
            self.time = struct.unpack("<I", stream.read(4))[0]
        self.services = struct.unpack("<Q", stream.read(8))[0]
        self.reserved = stream.read(12)
        self.ip = struct.unpack(">I", stream.read(4))[0]
        self.port = struct.unpack(">H", stream.read(2))[0]

    def get_key(self) -> bytes:
        """Get address key for map"""
        stream = DataStream()
        stream.write(self.reserved)
        stream.write(struct.pack(">I", self.ip))
        stream.write(struct.pack(">H", self.port))
        return bytes(stream.vch)

    def get_sockaddr(self) -> Tuple[str, int]:
        """Get socket address tuple"""
        ip_str = socket.inet_ntoa(struct.pack(">I", self.ip))
        port = socket.ntohs(self.port)
        return (ip_str, port)

    def is_ipv4(self) -> bool:
        """Check if IPv4 address"""
        return self.reserved == self.IPv4_PREFIX

    def is_routable(self) -> bool:
        """Check if routable address"""
        byte3 = (self.ip >> 24) & 0xFF
        byte2 = (self.ip >> 16) & 0xFF
        return not (byte3 == 10 or (byte3 == 192 and byte2 == 168))

    def to_string(self) -> str:
        """Convert to string"""
        ip_str = socket.inet_ntoa(struct.pack(">I", self.ip))
        port = socket.ntohs(self.port)
        return f"{ip_str}:{port}"

    def __eq__(self, other):
        if not isinstance(other, Address):
            return False
        return self.reserved == other.reserved and self.ip == other.ip and self.port == other.port

    def __hash__(self):
        return hash((self.reserved, self.ip, self.port))

    def __str__(self):
        return self.to_string()


class Inv:
    """Inventory item"""

    def __init__(self, inv_type: int = 0, hash_val: uint256 = None):
        self.type = inv_type
        self.hash = hash_val if hash_val else uint256(0)

    def serialize(self, stream: DataStream, n_type: int = 0, n_version: int = 101):
        """Serialize inventory"""
        stream.write(struct.pack("<i", self.type))
        self.hash.serialize(stream, n_type, n_version)

    def unserialize(self, stream: DataStream, n_type: int = 0, n_version: int = 101):
        """Unserialize inventory"""
        self.type = struct.unpack("<i", stream.read(4))[0]
        self.hash = uint256()
        self.hash.unserialize(stream, n_type, n_version)

    def is_known_type(self) -> bool:
        """Check if known type"""
        return 1 <= self.type < len(TYPE_NAMES)

    def get_command(self) -> str:
        """Get command string"""
        if not self.is_known_type():
            raise ValueError(f"Unknown inventory type {self.type}")
        return TYPE_NAMES[self.type]

    def to_string(self) -> str:
        """Convert to string"""
        return f"{self.get_command()} {self.hash.get_hex()[:14]}"

    def __lt__(self, other):
        if not isinstance(other, Inv):
            return False
        return self.type < other.type or (self.type == other.type and self.hash < other.hash)

    def __eq__(self, other):
        if not isinstance(other, Inv):
            return False
        return self.type == other.type and self.hash == other.hash

    def __hash__(self):
        return hash((self.type, self.hash))

    def __str__(self):
        return self.to_string()


# Global network state
f_client = False
n_local_services = NODE_NETWORK if not f_client else 0
addr_local_host: Optional[Address] = None
nodes: List["Node"] = []
nodes_lock = threading.Lock()
addresses: Dict[bytes, Address] = {}
addresses_lock = threading.Lock()
f_shutdown = False


def check_for_shutdown(thread_id: int = -1) -> bool:
    """
    Check if shutdown was requested and exit thread if so
    Matches Bitcoin v0.1 CheckForShutdown()
    """
    if f_shutdown:
        if thread_id != -1 and thread_id < len(threads_running):
            threads_running[thread_id] = False
        # In Python, threads exit when function returns
        return True
    return False


class Node:
    """Network node (peer connection)"""

    VERSION = 101

    def __init__(self, sock: socket.socket, addr: Address, inbound: bool = False):
        self.services = 0
        self.socket = sock
        self.v_send = DataStream(SER_NETWORK, self.VERSION)
        self.v_recv = DataStream(SER_NETWORK, self.VERSION)
        self.send_lock = threading.Lock()
        self.recv_lock = threading.Lock()
        self.push_pos = -1
        self.addr = addr
        self.version = 0
        self.is_client = False
        self.inbound = inbound
        self.is_network_node = False
        self.disconnect = False
        self.ref_count = 0
        self.release_time = 0
        from typing import Callable

        self.map_requests: Dict[uint256, Callable] = {}
        self.requests_lock = threading.Lock()

        # Address flooding
        self.addr_to_send: List[Address] = []
        self.addr_known: Set[Address] = set()

        # Inventory based relay
        self.inventory_known: Set[Inv] = set()
        self.inventory_known2: Set[Inv] = set()
        self.inventory_to_send: List[Inv] = []
        self.inventory_lock = threading.Lock()
        self.map_ask_for: Dict[int, Inv] = {}

        # Subscription
        self.subscribe: List[bool] = [False] * 256

        # Push version message
        from cryptogenesis.util import get_adjusted_time

        n_time = get_adjusted_time()
        if not inbound:
            n_time = get_adjusted_time()
        self.push_message("version", self.VERSION, n_local_services, n_time, addr)

    def add_ref(self, timeout: int = 0):
        """Add reference to node"""
        if timeout != 0:
            self.release_time = max(self.release_time, int(time.time()) + timeout)
        else:
            self.ref_count += 1

    def release(self):
        """Release reference to node"""
        self.ref_count -= 1

    def get_ref_count(self) -> int:
        """Get reference count"""
        from cryptogenesis.util import get_adjusted_time

        return max(self.ref_count, 0) + (1 if get_adjusted_time() < self.release_time else 0)

    def ready_to_disconnect(self) -> bool:
        """Check if ready to disconnect"""
        return self.disconnect or self.get_ref_count() <= 0

    def add_inventory_known(self, inv: Inv):
        """Add inventory to known set"""
        with self.inventory_lock:
            self.inventory_known.add(inv)

    def push_inventory(self, inv: Inv):
        """Push inventory to send"""
        with self.inventory_lock:
            if inv not in self.inventory_known:
                self.inventory_to_send.append(inv)

    def begin_message(self, command: str):
        """Begin sending a message"""
        with self.send_lock:
            if self.push_pos != -1:
                self.abort_message()
            self.push_pos = len(self.v_send.vch)
            header = MessageHeader(command, 0)
            header.serialize(self.v_send)

    def abort_message(self):
        """Abort current message"""
        if self.push_pos == -1:
            return
        with self.send_lock:
            self.v_send.vch = self.v_send.vch[: self.push_pos]
            self.push_pos = -1

    def end_message(self):
        """End sending a message"""
        if self.push_pos == -1:
            return

        with self.send_lock:
            # Patch in the size
            n_size = len(self.v_send.vch) - self.push_pos - 20  # sizeof(MessageHeader)
            size_bytes = struct.pack("<I", n_size)
            for i, byte in enumerate(size_bytes):
                self.v_send.vch[self.push_pos + 16 + i] = byte

            self.push_pos = -1

    def push_message(self, command: str, *args):
        """Push a message with arguments"""
        try:
            self.begin_message(command)
            for arg in args:
                if hasattr(arg, "serialize"):
                    arg.serialize(self.v_send, SER_NETWORK, self.VERSION)
                elif isinstance(arg, int):
                    self.v_send.write(struct.pack("<Q", arg))
                elif isinstance(arg, list):
                    from cryptogenesis.serialize import write_compact_size

                    write_compact_size(self.v_send.vch, len(arg))
                    for item in arg:
                        if hasattr(item, "serialize"):
                            item.serialize(self.v_send, SER_NETWORK, self.VERSION)
            self.end_message()
        except Exception:
            self.abort_message()
            raise

    def disconnect_node(self):
        """Disconnect this node"""
        print(f"disconnecting node {self.addr}")
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        self.disconnect = True


def connect_socket(addr: Address) -> Optional[socket.socket]:
    """Connect to a socket"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        ip_str, port = addr.get_sockaddr()
        sock.connect((ip_str, port))
        sock.settimeout(None)
        return sock
    except socket.error as e:
        # More detailed error reporting (matches Bitcoin v0.1)
        errno = getattr(e, "errno", None)
        if errno:
            print(f"Connect failed: {addr} (error {errno})")
        else:
            print(f"Connect failed: {addr} ({e})")
        return None
    except Exception as e:
        print(f"Connect failed: {addr} ({e})")
        return None


def find_node(ip: int) -> Optional[Node]:
    """Find node by IP"""
    with nodes_lock:
        for node in nodes:
            if node.addr.ip == ip:
                return node
    return None


def connect_node(addr: Address, timeout: int = 0) -> Optional[Node]:
    """Connect to a node"""
    if addr.ip == (addr_local_host.ip if addr_local_host else 0):
        return None

    # Look for existing connection
    pnode = find_node(addr.ip)
    if pnode:
        if timeout != 0:
            pnode.add_ref(timeout)
        else:
            pnode.add_ref()
        return pnode

    print(f"trying {addr}")

    # Connect
    sock = connect_socket(addr)
    if sock:
        print(f"connected {addr}")
        pnode = Node(sock, addr, False)
        if timeout != 0:
            pnode.add_ref(timeout)
        else:
            pnode.add_ref()
        with nodes_lock:
            nodes.append(pnode)
        with addresses_lock:
            if addr.get_key() in addresses:
                addresses[addr.get_key()].last_failed = 0
        return pnode
    else:
        with addresses_lock:
            if addr.get_key() in addresses:
                from cryptogenesis.util import get_adjusted_time

                addresses[addr.get_key()].last_failed = get_adjusted_time()
        return None


def relay_inventory(inv: Inv):
    """Relay inventory to all connected nodes"""
    with nodes_lock:
        for node in nodes:
            node.push_inventory(inv)


def add_address(addr: Address) -> bool:
    """Add address to address map"""
    if not addr.is_routable():
        return False
    if addr.ip == (addr_local_host.ip if addr_local_host else 0):
        return False

    with addresses_lock:
        key = addr.get_key()
        if key not in addresses:
            addresses[key] = addr
            return True
        else:
            addr_found = addresses[key]
            if (addr_found.services | addr.services) != addr_found.services:
                addr_found.services |= addr.services
                return True
    return False


# Thread management
threads_running = [False] * 10
listen_socket: Optional[socket.socket] = None


def thread_socket_handler(listen_sock: socket.socket):
    """Socket handler thread - handles I/O for all connections"""
    print("ThreadSocketHandler started")
    nodes_disconnected: List[Node] = []
    prev_node_count = 0

    while not f_shutdown:
        if check_for_shutdown(0):
            break
        # Disconnect nodes
        with nodes_lock:
            # Disconnect duplicate connections
            map_first: Dict[int, Node] = {}
            nodes_copy = list(nodes)
            for node in nodes_copy:
                if node.disconnect:
                    continue
                ip = node.addr.ip
                if ip in map_first and (addr_local_host is None or addr_local_host.ip < ip):
                    node_extra = map_first[ip]
                    if node_extra.get_ref_count() > (1 if node_extra.is_network_node else 0):
                        node_extra, node = node, node_extra

                    if node_extra.get_ref_count() <= (1 if node_extra.is_network_node else 0):
                        print(f"({len(nodes)} nodes) disconnecting duplicate: {node_extra.addr}")
                        if node_extra.is_network_node and not node.is_network_node:
                            node.add_ref()
                            node_extra.is_network_node, node.is_network_node = (
                                node.is_network_node,
                                node_extra.is_network_node,
                            )
                            node_extra.release()
                        node_extra.disconnect = True
                map_first[ip] = node

            # Disconnect unused nodes
            nodes_copy = list(nodes)
            for node in nodes_copy:
                if (
                    node.ready_to_disconnect()
                    and len(node.v_recv.vch) == 0
                    and len(node.v_send.vch) == 0
                ):
                    nodes.remove(node)
                    node.disconnect_node()
                    from cryptogenesis.util import get_adjusted_time

                    node.release_time = max(node.release_time, get_adjusted_time() + 5 * 60)
                    if node.is_network_node:
                        node.release()
                    nodes_disconnected.append(node)

            # Delete disconnected nodes
            nodes_disconnected_copy = list(nodes_disconnected)
            for node in nodes_disconnected_copy:
                if node.get_ref_count() <= 0:
                    try:
                        nodes_disconnected.remove(node)
                        del node
                    except Exception:
                        pass

        if len(nodes) != prev_node_count:
            prev_node_count = len(nodes)

        # Find which sockets have data
        import select

        try:
            read_list = [listen_sock]
            write_list = []
            with nodes_lock:
                for node in nodes:
                    if node.socket:
                        read_list.append(node.socket)
                        with node.send_lock:
                            if len(node.v_send.vch) > 0:
                                write_list.append(node.socket)

            if not read_list and not write_list:
                time.sleep(0.05)
                continue

            try:
                readable, writable, _ = select.select(read_list, write_list, [], 0.05)
            except (OSError, ValueError) as e:
                # Handle select errors (matches Bitcoin v0.1)
                errno = getattr(e, "errno", None)
                if errno:
                    print(f"select failed: {errno}")
                else:
                    print(f"select failed: {e}")
                # Reset select lists and continue
                time.sleep(0.05)
                continue

            # Accept new connections
            if listen_sock in readable:
                try:
                    sock, addr_tuple = listen_sock.accept()
                    ip_str, port = addr_tuple
                    ip = struct.unpack(">I", socket.inet_aton(ip_str))[0]
                    port_net = socket.htons(port)
                    addr = Address(ip, port_net)
                    print(f"accepted connection from {addr}")
                    node = Node(sock, addr, True)
                    node.add_ref()
                    with nodes_lock:
                        nodes.append(node)
                except socket.error as e:
                    # More detailed error reporting (matches Bitcoin v0.1)
                    errno = getattr(e, "errno", None)
                    if errno:
                        ewouldblock = getattr(socket, "EWOULDBLOCK", None)
                        if ewouldblock and errno != ewouldblock:
                            print(f"ERROR ThreadSocketHandler accept failed: {errno}")
                    else:
                        print(f"accept failed: {e}")
                except Exception as e:
                    print(f"accept failed: {e}")

            # Service each socket
            nodes_copy = []
            with nodes_lock:
                nodes_copy = list(nodes)

            for node in nodes_copy:
                if f_shutdown:
                    break
                sock = node.socket
                if not sock:
                    continue

                # Receive
                if sock in readable:
                    try:
                        with node.recv_lock:
                            data = sock.recv(0x10000)  # 64KB
                            if data:
                                node.v_recv.vch.extend(data)
                            else:
                                if not node.disconnect:
                                    print("recv: socket closed")
                                node.disconnect = True
                    except socket.error as e:
                        # EINTR is not available on all platforms
                        eintr = getattr(socket, "EINTR", None)
                        errnos: tuple = (socket.EWOULDBLOCK, socket.EAGAIN)
                        if eintr:
                            errnos = errnos + (eintr,)  # type: ignore[assignment]
                        if e.errno not in errnos:
                            if not node.disconnect:
                                # More detailed error reporting (matches Bitcoin v0.1)
                                errno = getattr(e, "errno", None)
                                if errno:
                                    print(f"recv failed: {errno}")
                                else:
                                    print(f"recv failed: {e}")
                            node.disconnect = True

                # Send
                if sock in writable:
                    try:
                        with node.send_lock:
                            if len(node.v_send.vch) > 0:
                                n_bytes = sock.send(bytes(node.v_send.vch))
                                if n_bytes > 0:
                                    node.v_send.vch = node.v_send.vch[n_bytes:]
                                elif node.ready_to_disconnect():
                                    node.v_send.vch.clear()
                    except socket.error as e:
                        # More detailed error reporting (matches Bitcoin v0.1)
                        errno = getattr(e, "errno", None)
                        if errno:
                            print(f"send error {errno}")
                        else:
                            print(f"send error: {e}")
                        if node.ready_to_disconnect():
                            node.v_send.vch.clear()

        except Exception as e:
            print(f"Socket handler error: {e}")
            time.sleep(0.1)

        time.sleep(0.01)


def thread_open_connections():
    """Connection opener thread - opens new connections"""
    print("ThreadOpenConnections started")
    max_connections = 15

    while not f_shutdown:
        if check_for_shutdown(1):
            break
        time.sleep(0.5)

        with nodes_lock:
            if len(nodes) >= max_connections or len(nodes) >= len(addresses):
                continue

        # Make a list of unique class C's
        ipc_mask = 0xFFFFFF00
        ipc_list = []
        with addresses_lock:
            prev_ipc = 0
            for addr in addresses.values():
                if not addr.is_ipv4():
                    continue
                ipc = addr.ip & ipc_mask
                if ipc != prev_ipc:
                    ipc_list.append(ipc)
                    prev_ipc = ipc

        if not ipc_list:
            continue

        # Choose a random class C
        import random

        success = False
        limit = len(ipc_list)
        while not success and limit > 0:
            limit -= 1
            ipc = random.choice(ipc_list)

            # Organize addresses in class C by IP
            map_ip: Dict[int, List[Address]] = {}
            with addresses_lock:
                delay = min((30 * 60) << len(nodes), 8 * 60 * 60)
                for addr in addresses.values():
                    if (addr.ip & ipc_mask) != ipc:
                        continue
                    randomizer = (addr.last_failed * addr.ip * 7777) % 20000
                    from cryptogenesis.util import get_adjusted_time

                    if get_adjusted_time() - addr.last_failed > delay * randomizer / 10000:
                        if addr.ip not in map_ip:
                            map_ip[addr.ip] = []
                        map_ip[addr.ip].append(addr)

            if not map_ip:
                break

            # Choose a random IP in the class C
            ip = random.choice(list(map_ip.keys()))

            # Try each port for this IP
            for addr_connect in map_ip[ip]:
                if (
                    addr_connect.ip == (addr_local_host.ip if addr_local_host else 0)
                    or not addr_connect.is_ipv4()
                    or find_node(addr_connect.ip)
                ):
                    continue

                node = connect_node(addr_connect)
                if not node:
                    continue
                node.is_network_node = True

                if addr_local_host and addr_local_host.is_routable():
                    # Advertise our address
                    node.push_message("addr", [addr_local_host])

                # Get addresses
                node.push_message("getaddr")

                success = True
                break

        if not success:
            time.sleep(2)


def process_messages(node: Node):
    """Process messages from a node"""
    with node.recv_lock:
        v_recv = node.v_recv
        if len(v_recv.vch) == 0:
            return True

    # Find message start
    while True:
        # Search for message start
        start_pos = -1
        for i in range(len(v_recv.vch) - 3):
            if bytes(v_recv.vch[i : i + 4]) == MESSAGE_START:
                start_pos = i
                break

        if start_pos == -1:
            # No message start found
            if len(v_recv.vch) > 20:
                print("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n")
                v_recv.vch = v_recv.vch[-20:]
            break

        if start_pos > 0:
            print(f"\n\nPROCESSMESSAGE SKIPPED {start_pos} BYTES\n\n")
            v_recv.vch = v_recv.vch[start_pos:]

        # Read header
        if len(v_recv.vch) < 20:
            break

        header = MessageHeader()
        header_stream = DataStream()
        header_stream.vch = bytearray(v_recv.vch[:20])
        header.unserialize(header_stream)

        if not header.is_valid():
            print(f"\n\nPROCESSMESSAGE: ERRORS IN HEADER {header.get_command()}\n\n\n")
            v_recv.vch = v_recv.vch[1:]  # Skip one byte and try again
            continue

        command = header.get_command()
        message_size = header.message_size

        if message_size > len(v_recv.vch) - 20:
            # Need more data
            break

        # Copy message to its own buffer
        message_data = bytes(v_recv.vch[20 : 20 + message_size])
        v_recv.vch = v_recv.vch[20 + message_size :]

        # Process message
        try:
            process_message(node, command, message_data)
        except Exception as e:
            print(f"ProcessMessage({command}, {message_size} bytes) FAILED: {e}")

    v_recv.compact()
    return True


def process_message(node: Node, command: str, message_data: bytes):
    """Process a single message"""
    print(f"received: {command:12s} ({len(message_data)} bytes)  ", end="")
    for i in range(min(len(message_data), 25)):
        print(f"{message_data[i]:02x} ", end="")
    print()

    stream = DataStream(SER_NETWORK, Node.VERSION)
    stream.vch = bytearray(message_data)

    if command == "version":
        # Can only do this once
        if node.version != 0:
            return False

        node.version = struct.unpack("<i", stream.read(4))[0]
        node.services = struct.unpack("<Q", stream.read(8))[0]
        n_time = struct.unpack("<q", stream.read(8))[0]

        # Add time data for clock skew adjustment
        from cryptogenesis.util import add_time_data

        add_time_data(node.addr.ip, n_time)

        addr_me = Address()
        addr_me.unserialize(stream, SER_NETWORK, Node.VERSION)

        if node.version == 0:
            return False

        node.v_send.n_version = min(node.version, Node.VERSION)
        node.v_recv.n_version = min(node.version, Node.VERSION)

        node.is_client = not (node.services & NODE_NETWORK)

        print(f"version addrMe = {addr_me}")

    elif node.version == 0:
        # Must have a version message before anything else
        return False

    elif command == "addr":
        from cryptogenesis.serialize import read_compact_size

        size, _ = read_compact_size(stream.vch, 0)
        stream.n_read_pos = stream.n_read_pos + (
            1 if size < 253 else (3 if size <= 0xFFFF else (5 if size <= 0xFFFFFFFF else 9))
        )
        v_addr = []
        for _ in range(size):
            addr = Address()
            addr.unserialize(stream, SER_NETWORK, Node.VERSION)
            v_addr.append(addr)

        # Store the new addresses
        for addr in v_addr:
            if f_shutdown:
                return True
            if add_address(addr):
                node.addr_known.add(addr)
                with nodes_lock:
                    for other_node in nodes:
                        if addr not in other_node.addr_known:
                            other_node.addr_to_send.append(addr)

    elif command == "inv":
        from cryptogenesis.serialize import read_compact_size

        size, _ = read_compact_size(stream.vch, 0)
        stream.n_read_pos = stream.n_read_pos + (
            1 if size < 253 else (3 if size <= 0xFFFF else (5 if size <= 0xFFFFFFFF else 9))
        )
        v_inv = []
        for _ in range(size):
            inv = Inv()
            inv.unserialize(stream, SER_NETWORK, Node.VERSION)
            v_inv.append(inv)

        for inv in v_inv:
            if f_shutdown:
                return True
            node.add_inventory_known(inv)
            print(f"  got inventory: {inv}")

            # Check if we already have this (AlreadyHave)
            if not already_have(inv):
                node.push_message("getdata", [inv])
            else:
                print(f"  already have: {inv}")

    elif command == "getdata":
        from cryptogenesis.serialize import read_compact_size

        size, _ = read_compact_size(stream.vch, 0)
        stream.n_read_pos = stream.n_read_pos + (
            1 if size < 253 else (3 if size <= 0xFFFF else (5 if size <= 0xFFFFFFFF else 9))
        )
        v_inv = []
        for _ in range(size):
            inv = Inv()
            inv.unserialize(stream, SER_NETWORK, Node.VERSION)
            v_inv.append(inv)

        for inv in v_inv:
            print(f"received getdata for: {inv}")
            if f_shutdown:
                return True

            if inv.type == MSG_BLOCK:
                from cryptogenesis.chain import get_chain

                chain = get_chain()
                block = chain.get_block(inv.hash)
                if block:
                    node.push_message("block", block)
                else:
                    print(f"  block {inv.hash.get_hex()[:14]} not found")
            elif inv.type == MSG_TX:
                from cryptogenesis.mempool import get_mempool

                mempool = get_mempool()
                tx = mempool.get_transaction(inv.hash)
                if tx:
                    node.push_message("tx", tx)
                else:
                    print(f"  tx {inv.hash.get_hex()[:14]} not found")

    elif command == "getblocks":
        from cryptogenesis.block import BlockLocator
        from cryptogenesis.chain import get_chain

        # Unserialize block locator and hash stop
        locator = BlockLocator()
        locator.unserialize(stream, SER_NETWORK, Node.VERSION)
        hash_stop = uint256()
        hash_stop.unserialize(stream, SER_NETWORK, Node.VERSION)

        chain = get_chain()
        chain.get_best_index()  # Get best index (used for validation)

        # Find the first block the caller has in the main chain
        pindex = locator.get_block_index()
        if pindex:
            # Start from the next block after the one they have
            pindex = pindex.next
        else:
            # They don't have any blocks, start from genesis
            pindex = chain.get_genesis_index()

        print(f"getblocks {pindex.height if pindex else -1} to {hash_stop.get_hex()[:14]}")

        # Send the rest of the chain
        inv_list = []
        while pindex:
            if f_shutdown:
                return True

            block_hash = pindex.get_block_hash()
            if block_hash == hash_stop:
                print(f"  getblocks stopping at {pindex.height} {block_hash.get_hex()[:14]}")
                break

            inv = Inv(MSG_BLOCK, block_hash)
            inv_list.append(inv)

            if pindex.next:
                pindex = pindex.next
            else:
                break

        if inv_list:
            node.push_message("inv", inv_list)

    elif command == "tx":
        from cryptogenesis.mempool import accept_transaction, get_mempool

        # Unserialize transaction
        tx = Transaction()
        tx.unserialize(stream, SER_NETWORK, Node.VERSION)

        inv = Inv(MSG_TX, tx.get_hash())
        node.add_inventory_known(inv)

        # Accept transaction
        success, missing_inputs = accept_transaction(tx, check_inputs=True, check_utxos=False)

        if success:
            # Relay transaction
            relay_inventory(inv)

            # Process any orphan transactions that depended on this one
            mempool = get_mempool()
            work_queue = [tx.get_hash()]

            for i in range(len(work_queue)):
                hash_prev = work_queue[i]
                orphan_hashes = mempool.get_orphan_transactions_by_prev(hash_prev)

                for orphan_hash in orphan_hashes:
                    orphan_data = mempool.get_orphan_transaction(orphan_hash)
                    if not orphan_data:
                        continue

                    # Deserialize orphan transaction
                    orphan_stream = DataStream(SER_NETWORK, Node.VERSION)
                    orphan_stream.vch = bytearray(orphan_data)
                    orphan_tx = Transaction()
                    try:
                        orphan_tx.unserialize(orphan_stream, SER_NETWORK, Node.VERSION)
                    except Exception:
                        continue

                    # Try to accept it
                    orphan_success, _ = accept_transaction(orphan_tx, check_inputs=True)
                    if orphan_success:
                        print(f"   accepted orphan tx {orphan_hash.get_hex()[:6]}")
                        orphan_inv = Inv(MSG_TX, orphan_hash)
                        relay_inventory(orphan_inv)
                        work_queue.append(orphan_hash)

            # Erase processed orphans
            for hash_val in work_queue:
                mempool.erase_orphan_transaction(hash_val)

        elif missing_inputs:
            # Store as orphan
            print(f"storing orphan tx {inv.hash.get_hex()[:6]}")
            mempool = get_mempool()
            mempool.add_orphan_transaction(message_data)

    elif command == "block":
        from cryptogenesis.block import Block
        from cryptogenesis.chain import get_chain

        # Unserialize block
        block = Block()
        block.unserialize(stream, SER_NETWORK, Node.VERSION)

        block_hash = block.get_hash()
        inv = Inv(MSG_BLOCK, block_hash)
        node.add_inventory_known(inv)

        # Process block
        chain = get_chain()
        if chain.process_block(block):
            # Relay if it's new
            relay_inventory(inv)

    elif command == "getaddr":
        node.addr_to_send.clear()
        from cryptogenesis.util import get_adjusted_time

        n_since = get_adjusted_time() - 60 * 60  # Last hour
        with addresses_lock:
            for addr in addresses.values():
                if f_shutdown:
                    return True
                if addr.time > n_since:
                    node.addr_to_send.append(addr)

    return True


def already_have(inv: Inv) -> bool:
    """
    Check if we already have this inventory item

    Args:
        inv: Inventory item to check

    Returns:
        True if we already have it, False otherwise
    """
    from cryptogenesis.chain import get_chain
    from cryptogenesis.mempool import get_mempool
    from cryptogenesis.utxo import get_txdb

    if inv.type == MSG_TX:
        # Check if transaction is in mempool or transaction database
        mempool = get_mempool()
        txdb = get_txdb()
        return mempool.has_transaction(inv.hash) or txdb.contains_tx(inv.hash)
    elif inv.type == MSG_BLOCK:
        # Check if block is in block index or orphan blocks
        chain = get_chain()
        if chain.has_block(inv.hash):
            return True
        # Check orphan blocks
        with chain.orphan_lock:
            return inv.hash in chain.orphan_blocks
    elif inv.type == MSG_REVIEW:
        # We always have reviews (not implemented)
        return True
    elif inv.type == MSG_PRODUCT:
        # Products not implemented in this version
        return False
    else:
        # Don't know what it is, just say we already got one
        return True


def send_messages(node: Node):
    """Send messages to a node"""
    # Send addresses
    if node.addr_to_send:
        addr_list = node.addr_to_send[:1000]  # Limit to 1000
        node.addr_to_send = node.addr_to_send[1000:]
        node.push_message("addr", addr_list)

    # Send inventory
    with node.inventory_lock:
        if node.inventory_to_send:
            inv_list = node.inventory_to_send[:1000]  # Limit to 1000
            node.inventory_to_send = node.inventory_to_send[1000:]
            node.push_message("inv", inv_list)

    return True


def thread_message_handler():
    """Message handler thread - processes incoming messages"""
    print("ThreadMessageHandler started")
    while not f_shutdown:
        if check_for_shutdown(2):
            break
        nodes_copy = []
        with nodes_lock:
            nodes_copy = list(nodes)

        for node in nodes_copy:
            if f_shutdown:
                break
            node.add_ref()

            # Receive messages
            process_messages(node)

            # Send messages
            send_messages(node)

            node.release()

        time.sleep(0.1)


def start_node() -> Tuple[bool, str]:
    """Start the network node"""
    global addr_local_host, listen_socket, f_shutdown

    f_shutdown = False
    error = ""

    # Get local host IP
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        ip = struct.unpack(">I", socket.inet_aton(local_ip))[0]
        port_net = socket.htons(DEFAULT_PORT)
        addr_local_host = Address(ip, port_net, n_local_services)
        print(f"addrLocalHost = {addr_local_host}")
    except Exception as e:
        error = f"Error: Unable to get IP address: {e}"
        print(error)
        return False, error

    # Create listening socket
    try:
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_socket.setblocking(False)
        ip_str, port = addr_local_host.get_sockaddr()
        listen_socket.bind((ip_str, port))
        listen_socket.listen(5)
        print(f"bound to addrLocalHost = {addr_local_host}\n")
    except socket.error as e:
        # More detailed error reporting (matches Bitcoin v0.1)
        errno = getattr(e, "errno", None)
        if errno:
            error = (
                f"Error: Couldn't open socket for incoming connections "
                f"(socket returned error {errno})"
            )
        else:
            error = f"Error: Couldn't open socket for incoming connections: {e}"
        print(error)
        return False, error
    except Exception as e:
        error = f"Error: Unable to bind to port: {e}"
        print(error)
        return False, error

    # Start threads
    try:
        socket_thread = threading.Thread(
            target=thread_socket_handler, args=(listen_socket,), daemon=True
        )
        socket_thread.start()
        threads_running[0] = True

        open_connections_thread = threading.Thread(target=thread_open_connections, daemon=True)
        open_connections_thread.start()
        threads_running[1] = True

        message_thread = threading.Thread(target=thread_message_handler, daemon=True)
        message_thread.start()
        threads_running[2] = True

        # Start IRC peer discovery (optional)
        irc_thread = threading.Thread(target=thread_irc_seed, daemon=True)
        irc_thread.start()
        threads_running[3] = True
    except Exception as e:
        error = f"Error: Failed to start threads: {e}"
        print(error)
        return False, error

    return True, ""


def stop_node():
    """Stop the network node"""
    global f_shutdown, listen_socket

    print("StopNode()")
    f_shutdown = True

    # Wait for threads to stop
    while any(threads_running):
        time.sleep(0.01)
    time.sleep(0.05)

    # Close listening socket
    if listen_socket:
        try:
            listen_socket.close()
        except Exception:
            pass
        listen_socket = None

    # Disconnect all nodes
    with nodes_lock:
        for node in list(nodes):
            node.disconnect_node()
        nodes.clear()

    return True


# IRC Peer Discovery (optional)
def encode_address_base58(addr: Address) -> str:
    """Encode address in base58 for IRC"""
    # Simplified base58 encoding - in production use proper base58
    import base64

    data = struct.pack(">I", addr.ip) + struct.pack(">H", addr.port)
    encoded = base64.b64encode(data).decode("ascii").rstrip("=")
    return f"u{encoded}"


def decode_address_base58(encoded: str) -> Optional[Address]:
    """Decode address from base58 IRC format"""
    if not encoded.startswith("u"):
        return None
    try:
        import base64

        # Add padding if needed
        encoded_b64 = encoded[1:] + "=="
        data = base64.b64decode(encoded_b64)
        if len(data) != 6:
            return None
        ip = struct.unpack(">I", data[:4])[0]
        port = struct.unpack(">H", data[4:6])[0]
        return Address(ip, port)
    except Exception:
        return None


def recv_line_irc(sock: socket.socket) -> Optional[str]:
    """Receive a line from IRC socket"""
    try:
        data = sock.recv(1)
        if not data:
            return None
        line = b""
        while data:
            if data == b"\n":
                continue
            if data == b"\r":
                return line.decode("utf-8", errors="ignore")
            line += data
            data = sock.recv(1)
        return line.decode("utf-8", errors="ignore") if line else None
    except Exception:
        return None


def thread_irc_seed():
    """IRC peer discovery thread"""
    print("ThreadIRCSeed started")
    while not f_shutdown:
        try:
            # Connect to IRC
            irc_host = "chat.freenode.net"
            irc_port = 6667

            try:
                irc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                irc_sock.settimeout(30)
                irc_sock.connect((irc_host, irc_port))
                irc_sock.settimeout(None)
            except Exception as e:
                print(f"IRC connect failed: {e}")
                time.sleep(60)
                continue

            # Wait for initial messages
            line = recv_line_irc(irc_sock)
            while line and not any(
                x in line
                for x in [
                    "Found your hostname",
                    "using your IP address instead",
                    "Couldn't look up your hostname",
                ]
            ):
                line = recv_line_irc(irc_sock)

            if not line:
                irc_sock.close()
                continue

            # Generate nickname
            if addr_local_host and addr_local_host.is_routable():
                str_my_name = encode_address_base58(addr_local_host)
            else:
                import random

                str_my_name = f"x{random.randint(0, 1000000000)}"

            # Send NICK and USER
            irc_sock.send(f"NICK {str_my_name}\r\n".encode())
            irc_sock.send(f"USER {str_my_name} 8 * : {str_my_name}\r\n".encode())

            # Wait for 004 (registration complete)
            line = recv_line_irc(irc_sock)
            while line and " 004 " not in line:
                line = recv_line_irc(irc_sock)

            if not line:
                irc_sock.close()
                continue

            time.sleep(0.5)

            # Join channel and get user list
            irc_sock.send("JOIN #bitcoin\r\n".encode())
            irc_sock.send("WHO #bitcoin\r\n".encode())

            # Process messages
            while not f_shutdown:
                line = recv_line_irc(irc_sock)
                if not line:
                    break

                if not line or line[0] != ":":
                    continue

                print(f"IRC {line}")

                words = line.split()
                if len(words) < 2:
                    continue

                name = ""

                # Handle WHO response (352)
                if words[1] == "352" and len(words) >= 8:
                    name = words[7][:16]  # Limited to 16 chars
                    print(f"GOT WHO: [{name}]  ", end="")

                # Handle JOIN
                if words[1] == "JOIN":
                    name = words[0][1:]  # Remove leading :
                    if "!" in name:
                        name = name.split("!")[0]
                    print(f"GOT JOIN: [{name}]  ", end="")

                # Decode address if it starts with 'u'
                if name.startswith("u"):
                    addr = decode_address_base58(name)
                    if addr:
                        if add_address(addr):
                            print("new  ", end="")
                        print(addr)
                    else:
                        print("decode failed")

            irc_sock.close()

        except Exception as e:
            print(f"IRC thread error: {e}")
            time.sleep(60)
