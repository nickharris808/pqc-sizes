"""Tests for the sizes / fragmentation / window arithmetic."""

from __future__ import annotations

import pytest

from pqc_sizes import (
    ALGORITHMS,
    TRANSPORTS,
    Credential,
    credential_bytes,
    fragments_for,
    max_concurrent_contexts,
    reassembly_window,
)

# --------------------------------------------------------------- sizes


def test_known_standard_sizes():
    """Anchor a few sizes so a careless edit to the table is caught."""
    assert ALGORITHMS["ML-KEM-768"].public_key == 1184
    assert ALGORITHMS["ML-KEM-768"].ciphertext_or_sig == 1088
    assert ALGORITHMS["ML-KEM-768"].shared_secret == 32
    assert ALGORITHMS["ML-DSA-65"].public_key == 1952
    assert ALGORITHMS["ML-DSA-65"].ciphertext_or_sig == 3309
    assert ALGORITHMS["Falcon-512"].ciphertext_or_sig == 752
    assert ALGORITHMS["SLH-DSA-SHA2-128f"].ciphertext_or_sig == 17088


def test_classical_share_fits_in_one_frame_but_pq_does_not():
    """The whole premise of the package, asserted."""
    x25519 = ALGORITHMS["X25519"].public_key
    assert fragments_for(x25519, TRANSPORTS["wifi-mgmt-frag"]) == 1

    pq = credential_bytes("ML-KEM-768", "ML-DSA-65")
    assert fragments_for(pq, TRANSPORTS["wifi-mgmt-frag"]) > 1


def test_category3_credential_total():
    """1184 + 1088 + 1952 + 3309 = 7533."""
    assert credential_bytes("ML-KEM-768", "ML-DSA-65") == 7533


def test_credential_breakdown_sums_to_total():
    cred = Credential(ALGORITHMS["ML-KEM-768"], ALGORITHMS["ML-DSA-65"])
    assert sum(cred.breakdown.values()) == cred.total_bytes


def test_credential_options_reduce_total():
    full = Credential(ALGORITHMS["ML-KEM-768"], ALGORITHMS["ML-DSA-65"])
    lean = Credential(
        ALGORITHMS["ML-KEM-768"],
        ALGORITHMS["ML-DSA-65"],
        include_kem_ciphertext=False,
        include_sig_public_key=False,
    )
    assert lean.total_bytes < full.total_bytes
    assert lean.total_bytes == 1184 + 3309


# ---------------------------------------------------------- fragments


def test_fragments_rounds_up():
    assert fragments_for(7533, 384) == 20      # 19.6 -> 20
    assert fragments_for(768, 384) == 2        # exact
    assert fragments_for(385, 384) == 2        # one byte over
    assert fragments_for(1, 384) == 1


def test_fragments_zero_object_is_zero():
    assert fragments_for(0, 384) == 0


@pytest.mark.parametrize("bad", [0, -1])
def test_fragments_rejects_nonpositive_frame(bad):
    with pytest.raises(ValueError):
        fragments_for(100, bad)


def test_fragments_rejects_negative_object():
    with pytest.raises(ValueError):
        fragments_for(-1, 384)


def test_ethernet_credential_fragments():
    """A cat-3 credential over standard Ethernet: 7533 / 1500 -> 6."""
    assert fragments_for(7533, TRANSPORTS["ethernet"]) == 6


def test_hash_based_signature_is_the_pathological_case():
    """SLH-DSA fast is 17088 B: ~45 fragments at the Wi-Fi unit."""
    assert fragments_for(17088, TRANSPORTS["wifi-mgmt-frag"]) == 45


# ------------------------------------------------------------- window


def test_window_non_empty_and_recommends_ceiling():
    win = reassembly_window(12000, 65536, 4)
    assert win.ceiling == 16384          # 65536 // 4
    assert not win.is_empty
    assert win.recommended == 16384
    assert win.admits(16384)
    assert win.admits(12000)


def test_window_excludes_values_outside_the_interval():
    win = reassembly_window(12000, 65536, 4)
    assert not win.admits(11999)         # below floor: refuses honest peers
    assert not win.admits(16385)         # above ceiling: budget exceeded


def test_window_goes_empty_at_three_contexts_on_a_constrained_device():
    """The shareable result: a 32 KiB budget cannot serve 3 concurrent
    contexts at a 12 KB object."""
    assert not reassembly_window(12000, 32768, 1).is_empty   # ceiling 32768
    assert not reassembly_window(12000, 32768, 2).is_empty   # ceiling 16384
    assert reassembly_window(12000, 32768, 3).is_empty       # ceiling 10922
    assert reassembly_window(12000, 32768, 4).is_empty       # ceiling  8192


def test_empty_window_has_no_recommendation_and_explains_why():
    win = reassembly_window(12000, 32768, 3)
    assert win.is_empty
    assert win.recommended is None
    text = win.explain()
    assert "EMPTY WINDOW" in text
    assert "10,922" in text              # the ceiling, comma-formatted


def test_empty_window_advice_names_a_concurrency_that_is_actually_safe():
    """Regression: the advice used to say 'below N' where N itself was safe."""
    win = reassembly_window(12000, 32768, 3)
    safe = max_concurrent_contexts(12000, 32768)          # 2
    assert f"at most {safe}" in win.explain()
    assert not reassembly_window(12000, 32768, safe).is_empty


def test_empty_window_advice_when_even_one_context_cannot_fit():
    """Object alone exceeds the budget: reducing concurrency cannot help."""
    win = reassembly_window(20000, 8192, 1)
    assert win.is_empty
    assert "cannot help" in win.explain()


def test_explain_is_readable_when_non_empty():
    text = reassembly_window(12000, 65536, 4).explain()
    assert "16,384" in text
    assert "EMPTY" not in text


@pytest.mark.parametrize(
    "obj,budget,conc",
    [(0, 65536, 4), (12000, 0, 4), (12000, 65536, 0), (-1, 65536, 4)],
)
def test_window_rejects_nonpositive_inputs(obj, budget, conc):
    with pytest.raises(ValueError):
        reassembly_window(obj, budget, conc)


# -------------------------------------------------- derived concurrency


def test_max_concurrency_is_derived_not_guessed():
    assert max_concurrent_contexts(12000, 32768) == 2
    assert max_concurrent_contexts(12000, 65536) == 5
    assert max_concurrent_contexts(16384, 65536) == 4


def test_max_concurrency_agrees_with_window_emptiness():
    """Cross-check: the derived limit is exactly the last non-empty context count."""
    obj, budget = 12000, 32768
    limit = max_concurrent_contexts(obj, budget)
    assert not reassembly_window(obj, budget, limit).is_empty
    assert reassembly_window(obj, budget, limit + 1).is_empty


def test_slh_dsa_credential_overflows_a_16k_ceiling():
    """A hash-based credential does not fit the classic 16 KiB ceiling."""
    big = credential_bytes("ML-KEM-768", "SLH-DSA-SHA2-128f")
    win = reassembly_window(big, 65536, 4)
    assert big > 16384
    assert win.is_empty
