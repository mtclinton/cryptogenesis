"""
Private Network Configuration

Custom network parameters for running an isolated Bitcoin blockchain.
This creates a completely separate network from Bitcoin mainnet/testnet.
"""

from cryptogenesis.uint256 import uint256

# ============================================================================
# PRIVATE NETWORK PARAMETERS
# ============================================================================

# Network magic bytes (different from Bitcoin mainnet 0xF9BEB4D9)
# Using "CRYP" in ASCII: 0x43525950
MESSAGE_START = bytes([0x43, 0x52, 0x59, 0x50])

# Private network port (different from mainnet 8333)
DEFAULT_PORT = 18333

# ============================================================================
# BLOCKCHAIN PARAMETERS
# ============================================================================

# Custom genesis block hash for private network
# This will be calculated when we create the custom genesis block
HASH_GENESIS_BLOCK_PRIVATE = None  # Will be set after genesis creation

# Private network name/identifier
NETWORK_NAME = "cryptogenesis-private"

# ============================================================================
# MINING PARAMETERS
# ============================================================================

# Easier difficulty for private network (higher target)
# Mainnet target: 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
# Private network target: Much higher (easier) difficulty
PRIVATE_NETWORK_BITS = 0x2100FFFF  # Extremely easy - should find blocks quickly

# ============================================================================
# NETWORK FEATURES
# ============================================================================

# Enable faster block times for testing (10 minutes instead of 10 minutes... wait, Bitcoin is 10 minutes)
# Actually, keep standard 10 minutes but allow faster mining for testing
ALLOW_INSTANT_BLOCKS = True  # Allow blocks with timestamp in future for testing

# ============================================================================
# GENESIS BLOCK PARAMETERS
# ============================================================================

# Custom genesis block timestamp
GENESIS_BLOCK_TIME_PRIVATE = 1609459200  # 2021-01-01 00:00:00 UTC

# Custom genesis block nonce (will be calculated)
GENESIS_BLOCK_NONCE_PRIVATE = None  # Will be mined

# Custom coinbase message
GENESIS_COINBASE_MESSAGE = b"Cryptogenesis Private Network Genesis Block - 2021"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def get_private_network_config():
    """
    Get all private network configuration parameters.

    Returns:
        dict: Dictionary containing all private network parameters
    """
    return {
        "message_start": MESSAGE_START,
        "default_port": DEFAULT_PORT,
        "network_name": NETWORK_NAME,
        "genesis_bits": PRIVATE_NETWORK_BITS,
        "genesis_time": GENESIS_BLOCK_TIME_PRIVATE,
        "allow_instant_blocks": ALLOW_INSTANT_BLOCKS,
        "coinbase_message": GENESIS_COINBASE_MESSAGE,
    }


def is_private_network():
    """
    Check if we're running in private network mode.
    This function will be called to determine network mode.

    Returns:
        bool: True if running private network, False otherwise
    """
    # This will be overridden by command line argument
    return False
