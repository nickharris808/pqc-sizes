"""Post-quantum object sizes, fragmentation arithmetic, and the reassembly window.

Everything here is arithmetic over measured, standards-conformant object sizes. There
is no cryptography in this package and it makes no security claim about your protocol.

Three questions it answers:

  1. Does my post-quantum credential fit in one frame?  (Almost never.)
  2. How many fragments will it become on my transport?
  3. What reassembly capacity may I safely allow -- and is that interval EMPTY?

The third is the interesting one. A receiver holding partial, not-yet-authenticated
reassembly state needs a capacity cap. That cap has *two* boundaries:

    floor   = the largest legitimate object you must accept
    ceiling = global reassembly budget / worst-case concurrent contexts

A cap below the floor refuses honest peers. A cap above the ceiling lets concurrent
sessions exhaust the budget. If floor > ceiling the window is EMPTY and no cap works --
which is a design answer, not an error: raise the budget, cut concurrency, or pick
smaller objects.

The ceiling formulation is the non-obvious half. The intuitive bound is per-object; that
is wrong, because exposure is retention x concurrency, not retention alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil

__all__ = [
    "ALGORITHMS",
    "TRANSPORTS",
    "Algorithm",
    "Credential",
    "Window",
    "credential_bytes",
    "fragments_for",
    "max_concurrent_contexts",
    "reassembly_window",
]


@dataclass(frozen=True)
class Algorithm:
    """A standardized post-quantum (or classical) algorithm and its wire sizes."""

    name: str
    kind: str  # "kem" | "sig" | "classical-kex" | "classical-sig"
    category: int | None  # NIST security category, None for classical
    public_key: int
    ciphertext_or_sig: int
    shared_secret: int | None = None

    @property
    def label(self) -> str:
        return f"{self.name} (cat {self.category})" if self.category else self.name


# Sizes in bytes, from standards-conformant implementations.
ALGORITHMS: dict[str, Algorithm] = {
    a.name: a
    for a in (
        Algorithm("ML-KEM-512", "kem", 1, 800, 768, 32),
        Algorithm("ML-KEM-768", "kem", 3, 1184, 1088, 32),
        Algorithm("ML-KEM-1024", "kem", 5, 1568, 1568, 32),
        Algorithm("ML-DSA-44", "sig", 2, 1312, 2420),
        Algorithm("ML-DSA-65", "sig", 3, 1952, 3309),
        Algorithm("ML-DSA-87", "sig", 5, 2592, 4627),
        Algorithm("Falcon-512", "sig", 1, 897, 752),
        Algorithm("Falcon-1024", "sig", 5, 1793, 1462),
        Algorithm("SLH-DSA-SHA2-128s", "sig", 1, 32, 7856),
        Algorithm("SLH-DSA-SHA2-128f", "sig", 1, 32, 17088),
        Algorithm("Classic-McEliece-348864", "kem", 1, 261120, 96, 32),
        Algorithm("X25519", "classical-kex", None, 32, 32, 32),
        Algorithm("ECDSA-P256", "classical-sig", None, 65, 72),
    )
}

# Representative transports: name -> usable payload bytes per frame.
TRANSPORTS: dict[str, int] = {
    "wifi-mgmt-frag": 384,      # 802.11 management-frame fragment payload
    "wifi-mtu": 2304,           # 802.11 MSDU
    "ethernet": 1500,           # standard Ethernet MTU
    "ethernet-jumbo": 9000,
    "ble-att": 251,             # BLE 5 ATT MTU
    "matter-btp": 244,          # Matter BTP segment payload
    "lorawan": 51,              # LoRaWAN DR0 payload
    "usb-hid": 64,
    "coap-dtls": 1152,
}


@dataclass(frozen=True)
class Credential:
    """A composite credential: KEM public key + ciphertext + signature key + signature."""

    kem: Algorithm
    sig: Algorithm
    include_kem_ciphertext: bool = True
    include_sig_public_key: bool = True

    @property
    def total_bytes(self) -> int:
        total = self.kem.public_key
        if self.include_kem_ciphertext:
            total += self.kem.ciphertext_or_sig
        if self.include_sig_public_key:
            total += self.sig.public_key
        total += self.sig.ciphertext_or_sig
        return total

    @property
    def breakdown(self) -> dict[str, int]:
        parts = {f"{self.kem.name} public key": self.kem.public_key}
        if self.include_kem_ciphertext:
            parts[f"{self.kem.name} ciphertext"] = self.kem.ciphertext_or_sig
        if self.include_sig_public_key:
            parts[f"{self.sig.name} public key"] = self.sig.public_key
        parts[f"{self.sig.name} signature"] = self.sig.ciphertext_or_sig
        return parts


def credential_bytes(kem: str, sig: str, **kwargs) -> int:
    """Total on-wire bytes for a KEM+signature credential."""
    return Credential(ALGORITHMS[kem], ALGORITHMS[sig], **kwargs).total_bytes


def fragments_for(object_bytes: int, frame_payload: int) -> int:
    """Number of fragments an object becomes on a transport.

    Raises ValueError on a non-positive frame payload -- a transport that carries
    nothing is a caller error, not something to return 0 for.
    """
    if object_bytes < 0:
        raise ValueError("object_bytes must be non-negative")
    if frame_payload <= 0:
        raise ValueError("frame_payload must be positive")
    if object_bytes == 0:
        return 0
    return ceil(object_bytes / frame_payload)


@dataclass(frozen=True)
class Window:
    """The admissible reassembly-capacity interval [floor, ceiling]."""

    floor: int
    ceiling: int
    budget: int
    concurrency: int

    @property
    def is_empty(self) -> bool:
        return self.floor > self.ceiling

    @property
    def recommended(self) -> int | None:
        """Largest safe cap, or None when no cap is safe."""
        return None if self.is_empty else self.ceiling

    def admits(self, cap: int) -> bool:
        return not self.is_empty and self.floor <= cap <= self.ceiling

    def explain(self) -> str:
        if self.is_empty:
            deficit = self.floor - self.ceiling
            safe_conc = self.budget // self.floor
            if safe_conc >= 1:
                conc_advice = f"reduce concurrency to at most {safe_conc}"
            else:
                # Even one context does not fit: the object alone exceeds the budget.
                conc_advice = (
                    "reducing concurrency cannot help -- a single object "
                    f"({self.floor:,} B) already exceeds the budget"
                )
            return (
                f"EMPTY WINDOW: floor {self.floor:,} B > ceiling {self.ceiling:,} B "
                f"(short by {deficit:,} B). No capacity cap is both feasible and safe. "
                f"Raise the budget to at least {self.floor * self.concurrency:,} B, "
                f"{conc_advice}, or choose a smaller credential."
            )
        return (
            f"window [{self.floor:,}, {self.ceiling:,}] B; "
            f"recommended cap {self.ceiling:,} B "
            f"(budget {self.budget:,} B / {self.concurrency} concurrent contexts)"
        )


def reassembly_window(
    largest_legitimate_object: int, memory_budget: int, concurrency: int
) -> Window:
    """Compute the two-sided reassembly-capacity window.

    floor   = largest legitimate object the deployment must accept
    ceiling = floor_div(memory_budget, worst-case concurrent reassembly contexts)
    """
    if largest_legitimate_object <= 0:
        raise ValueError("largest_legitimate_object must be positive")
    if memory_budget <= 0:
        raise ValueError("memory_budget must be positive")
    if concurrency <= 0:
        raise ValueError("concurrency must be positive")
    return Window(
        floor=largest_legitimate_object,
        ceiling=memory_budget // concurrency,
        budget=memory_budget,
        concurrency=concurrency,
    )


def max_concurrent_contexts(largest_legitimate_object: int, memory_budget: int) -> int:
    """Highest concurrency for which a non-empty window still exists.

    This *derives* a device's safe concurrency limit instead of leaving it to be
    discovered in the field.
    """
    if largest_legitimate_object <= 0 or memory_budget <= 0:
        raise ValueError("inputs must be positive")
    return memory_budget // largest_legitimate_object
