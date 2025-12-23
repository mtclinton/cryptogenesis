"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Utility functions - GetTime, GetAdjustedTime, AddTimeData, error
"""

import time
from threading import Lock
from typing import Set

# Global time offset (matches Bitcoin v0.1)
_n_time_offset: int = 0
_time_offset_lock = Lock()

# Time offset samples (one per IP)
_v_time_offsets: list[int] = []
_set_known_ips: Set[int] = set()


def get_time() -> int:
    """
    Get current time as integer (Unix timestamp)
    Equivalent to GetTime() in Bitcoin v0.1
    """
    return int(time.time())


def get_adjusted_time() -> int:
    """
    Get adjusted time accounting for clock skew
    Equivalent to GetAdjustedTime() in Bitcoin v0.1

    Returns:
        Current time + time offset (adjusted for network clock skew)
    """
    with _time_offset_lock:
        # Cap time offset to reasonable range (±2 hours) to prevent overflow
        # This prevents blocks from being rejected due to invalid timestamps
        capped_offset = max(-7200, min(7200, _n_time_offset))
        return get_time() + capped_offset


def add_time_data(ip: int, n_time: int) -> None:
    """
    Add time data from a network peer to adjust for clock skew
    Equivalent to AddTimeData() in Bitcoin v0.1

    Args:
        ip: IP address of the peer (as integer)
        n_time: Time reported by the peer
    """
    global _n_time_offset, _v_time_offsets, _set_known_ips

    n_offset_sample = n_time - get_time()

    with _time_offset_lock:
        # Ignore duplicates (one sample per IP)
        if ip in _set_known_ips:
            return
        _set_known_ips.add(ip)

        # Add data
        if not _v_time_offsets:
            _v_time_offsets.append(0)  # Start with 0 offset
        _v_time_offsets.append(n_offset_sample)

        print(
            f"Added time data, samples {len(_v_time_offsets)}, "
            f"ip {ip:08x}, offset {n_offset_sample:+d} ({n_offset_sample // 60:+d} minutes)"
        )

        # Calculate median when we have 5+ samples and odd number
        if len(_v_time_offsets) >= 5 and len(_v_time_offsets) % 2 == 1:
            sorted_offsets = sorted(_v_time_offsets)
            n_median = sorted_offsets[len(sorted_offsets) // 2]
            _n_time_offset = n_median

            # Warn if offset is large (5 minutes)
            abs_median = n_median if n_median > 0 else -n_median
            if abs_median > 5 * 60:
                # Only let other nodes change our clock so far before we
                # go to the NTP servers
                # TODO: Get time from NTP servers, then set a flag
                #   to make sure it doesn't get changed again
                pass

            # Debug output (matches original)
            offset_str = "  ".join(f"{n:+d}" for n in sorted_offsets)
            print(
                f"{offset_str}  |  nTimeOffset = {_n_time_offset:+d}  "
                f"({_n_time_offset // 60:+d} minutes)"
            )


def error(format_str: str, *args) -> bool:
    """
    Error reporting function (matches Bitcoin v0.1 error())

    Formats error message and prints it with "ERROR: " prefix.
    Always returns False for use in return statements.

    Args:
        format_str: Format string (supports %s, %d, etc.)
        *args: Arguments for format string

    Returns:
        Always returns False

    Example:
        if condition:
            return error("Operation failed: %s", reason)
    """
    # Format the message
    try:
        message = format_str % args if args else format_str
    except (TypeError, ValueError):
        # Fallback if formatting fails
        message = format_str + " " + " ".join(str(arg) for arg in args)

    # Print with ERROR prefix (matches Bitcoin v0.1)
    print(f"ERROR: {message}")
    return False
