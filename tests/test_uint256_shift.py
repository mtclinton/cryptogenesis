"""
Phase 0 known-answer pins for uint256 left-shift (documents a real bug).

uint256.__lshift__ currently (a) seeds the result with the operand instead of
zero and (b) never masks lanes to 32 bits, so it leaks the un-shifted low bits
and overflows struct.pack on some inputs. These known-answer tests use Python's
native bigint as the oracle and FAIL until the Phase 1 fix; they pin the exact
correct behavior, including the proof-of-work target derived from compact 'bits'
(the consensus-critical use of the shift in Block.get_target).
"""

from .context import cryptogenesis

uint256 = cryptogenesis.uint256
Block = cryptogenesis.Block


def test_left_shift_small():
    # 1 << 8 == 0x100 (today leaks the operand and yields 0x101).
    assert (uint256(1) << 8).get_hex() == format(1 << 8, "064x")


def test_left_shift_lane_boundary():
    # 1 << 32 crosses a 32-bit lane (today yields 0x1_0000_0001).
    assert (uint256(1) << 32).get_hex() == format(1 << 32, "064x")


def test_left_shift_two_lanes():
    # 1 << 64 spans two lanes (today yields 1 + 2**64).
    assert (uint256(1) << 64).get_hex() == format(1 << 64, "064x")


def test_target_from_compact_bits():
    # Compact 0x1D00FFFF -> target 0x00000000FFFF0000...0000 (mainnet difficulty-1).
    # Today the broken shift leaks ...ffff into the low lane, making the target
    # slightly too easy.
    blk = Block()
    blk.bits = 0x1D00FFFF
    expected = "00000000ffff0000000000000000000000000000000000000000000000000000"
    assert blk.get_target().get_hex() == expected
    # Cross-check against the bigint oracle: mantissa 0x00ffff shifted by the
    # compact exponent.
    assert blk.get_target().get_hex() == format(0x00FFFF << (8 * (0x1D - 3)), "064x")
