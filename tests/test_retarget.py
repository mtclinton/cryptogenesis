"""
Phase 1 pins for difficulty retargeting (block.py).

Covers the compact<->target round-trip and the retarget scaling/clamping that
get_next_work_required used to no-op. Equal timespan keeps difficulty; a longer
timespan eases it; a shorter one tightens it; both bounded by 4x and the PoW
limit.
"""

from .context import cryptogenesis  # noqa: F401

from cryptogenesis.block import (
    POW_LIMIT_BITS,
    calculate_next_work,
    compact_to_target,
    target_to_compact,
)

TARGET_TIMESPAN = 14 * 24 * 60 * 60  # two weeks


def test_compact_target_round_trip():
    for bits in (0x1D00FFFF, 0x1B0404CB, 0x1C7FFF00):
        assert target_to_compact(compact_to_target(bits)) == bits


def test_pow_limit_target_is_difficulty_one():
    # 0x1D00FFFF decodes to the canonical difficulty-1 target.
    expected = int("00000000ffff0000000000000000000000000000000000000000000000000000", 16)
    assert compact_to_target(POW_LIMIT_BITS) == expected


def test_equal_timespan_keeps_difficulty():
    # A sub-limit difficulty held over exactly the target timespan is unchanged.
    assert calculate_next_work(0x1B0404CB, TARGET_TIMESPAN, TARGET_TIMESPAN) == 0x1B0404CB


def test_slow_blocks_ease_difficulty():
    # Blocks took longer than target -> larger target (easier), clamped to 4x.
    new_bits = calculate_next_work(0x1B0404CB, TARGET_TIMESPAN * 8, TARGET_TIMESPAN)
    assert compact_to_target(new_bits) > compact_to_target(0x1B0404CB)
    # 8x is clamped to 4x.
    assert compact_to_target(new_bits) == compact_to_target(
        calculate_next_work(0x1B0404CB, TARGET_TIMESPAN * 4, TARGET_TIMESPAN)
    )


def test_fast_blocks_tighten_difficulty():
    # Blocks faster than target -> smaller target (harder), clamped to 1/4.
    new_bits = calculate_next_work(0x1B0404CB, TARGET_TIMESPAN // 8, TARGET_TIMESPAN)
    assert compact_to_target(new_bits) < compact_to_target(0x1B0404CB)


def test_retarget_never_exceeds_pow_limit():
    # Even an enormous timespan cannot make the target easier than the PoW limit.
    new_bits = calculate_next_work(POW_LIMIT_BITS, TARGET_TIMESPAN * 4, TARGET_TIMESPAN)
    assert compact_to_target(new_bits) <= compact_to_target(POW_LIMIT_BITS)
