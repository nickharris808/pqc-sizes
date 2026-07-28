# pqc-sizes

[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://pypi.org/project/pqc-sizes/)
[![tests](https://img.shields.io/badge/tests-53%20passing-brightgreen.svg)](tests/)
[![deps](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](pyproject.toml)

**Your post-quantum credential doesn't fit in one frame. Find out what that costs you — in 5 seconds.**

```
$ pqc-sizes window --largest-object 12000 --budget 32768 --concurrency 3
EMPTY WINDOW: floor 12,000 B > ceiling 10,922 B (short by 1,078 B). No
capacity cap is both feasible and safe. Raise the budget to at least 36,000 B,
reduce concurrency to at most 2, or choose a smaller credential.
```

It exits **1** when the window is empty, so it works as a CI gate as-is.

Zero dependencies. Pure arithmetic. No crypto, no network, no telemetry.

---

## Why this exists

An X25519 share is 32 bytes and fits in a single frame. A category-3 post-quantum
credential — KEM public key, KEM ciphertext, signature public key, signature — is
**7,533 bytes**, and becomes **20 fragments** on an 802.11 management-frame path.

That changes something structural, not just quantitative. A receiver now holds
attacker-influenced partial state *before* it can authenticate that state. So it needs a
cap on reassembly memory. And that cap has **two** boundaries, not one:

```
floor   = the largest legitimate object you must accept
ceiling = global reassembly budget / worst-case concurrent contexts
```

Below the floor you refuse honest peers. Above the ceiling concurrent sessions exhaust
your budget. **If floor > ceiling the interval is empty and no cap works** — which is a
design answer, not an error.

Most teams reach for a per-object bound. That's the wrong shape: exposure is
retention × concurrency, not retention alone.

## Install

```bash
pip install pqc-sizes            # once published
pip install -e .                 # from a clone, today
```

## 30-second quickstart

```bash
pqc-sizes credential --kem ML-KEM-768 --sig ML-DSA-65   # how big is it?
pqc-sizes fragments wifi-mgmt-frag --kem ML-KEM-768 --sig ML-DSA-65
pqc-sizes sweep --largest-object 12000 --budget 32768 --max-concurrency 4
```

## Worked example — actual output

```
$ pqc-sizes credential --kem ML-KEM-768 --sig ML-DSA-65
credential: ML-KEM-768 + ML-DSA-65
  ML-KEM-768 public key                  1,184 B
  ML-KEM-768 ciphertext                  1,088 B
  ML-DSA-65 public key                   1,952 B
  ML-DSA-65 signature                    3,309 B
  TOTAL                                  7,533 B

$ pqc-sizes fragments wifi-mgmt-frag --kem ML-KEM-768 --sig ML-DSA-65
ML-KEM-768+ML-DSA-65 credential over wifi-mgmt-frag (384 B/frame): 20 fragments
  -> fragmentation is mandatory; the receiver holds partial, unauthenticated
     state across 20 frames

$ pqc-sizes sweep --largest-object 12000 --budget 32768 --max-concurrency 4
largest legitimate object: 12,000 B   budget: 32,768 B

 contexts      ceiling   window
--------------------------------------------
        1       32,768   ok
        2       16,384   ok
        3       10,922   EMPTY
        4        8,192   EMPTY

window becomes EMPTY at 3 concurrent contexts -- that is this device's derived
concurrency limit.
```

**That last line is the point.** You didn't discover your concurrency limit by shipping
and watching devices fall over. You derived it in one command.

## Use it as a library

```python
from pqc_sizes import credential_bytes, fragments_for, reassembly_window

credential_bytes("ML-KEM-768", "ML-DSA-65")        # 7533
fragments_for(7533, 1500)                          # 6  (standard Ethernet)

win = reassembly_window(largest_legitimate_object=12000,
                        memory_budget=65536, concurrency=4)
win.ceiling      # 16384
win.is_empty     # False
win.admits(16385)  # False -- one byte over the budget
```

`window` exits **1** when the interval is empty, so it drops straight into CI.

## Machine-readable output

Every subcommand takes a global `--json`, placed **before** the subcommand:

```
$ pqc-sizes --json window --largest-object 12000 --budget 32768 --concurrency 3
{
  "floor": 12000,
  "ceiling": 10922,
  "budget": 32768,
  "concurrency": 3,
  "empty": true,
  "recommended_cap": null,
  "max_safe_concurrency": 2
}
```

The exit code still carries the verdict in `--json` mode, so you can pipe the
body to `jq` and branch on `$?` at the same time.

## What's included

**Algorithms** — ML-KEM 512/768/1024, ML-DSA 44/65/87, Falcon 512/1024, SLH-DSA
128s/128f, Classic McEliece, plus X25519 and ECDSA-P256 for comparison.

**Transports** — 802.11 management fragment (384 B) and MSDU (2304 B), Ethernet
(1500/9000 B), BLE ATT (251 B), Matter BTP (244 B), LoRaWAN DR0 (51 B), USB HID (64 B),
CoAP/DTLS (1152 B). Or pass a raw byte count.

## Scope

Arithmetic over published object sizes. It does **not** inspect your implementation,
verify anything cryptographically, or make a security claim about your protocol. A
non-empty window means a cap *exists* — not that your code enforces it.

## Tests

```bash
pip install -e ".[dev]" && pytest    # 53 passed
```

## Where this comes from

Extracted from a research lab on post-quantum authentication for constrained and
wireless devices. The bound this sizing rule feeds is machine-checked in Lean
(`bounded`, `naive_unbounded`, `gated_le_naive`, `separation`) and re-verifiable
on-device without a solver.

**This package tells you what cap to pick. It does not enforce it.** Enforcing it —
along with the rest of the post-quantum migration failure surface: downgrade,
key reinstallation, fragment splicing, roaming forward secrecy, multi-link key
separation — is what the closed core does. See
[`pqc-dos-embedded`](https://github.com/nickharris808/pqc-dos-embedded) for what enforcement looks like on a 64 KB
device.

Relevant subject matter is covered by a filed provisional patent application.
For commercial use, open a [GitHub Discussion](https://github.com/nickharris808) or an issue.

---

## The PQC migration toolkit

Nine free tools for teams moving authenticated key exchange to post-quantum. They **find and measure**; they do not repair.

| Tool | What it does | Where |
|---|---|---|
| **pqc-sizes** ← you are here | Sizes, fragment counts, and the two-sided reassembly window | PyPI |
| [pqc-sizes-js](https://github.com/nickharris808/pqc-sizes-js) | The same arithmetic for Node and the browser | npm |
| [pqc-guard-action](https://github.com/nickharris808/pqc-guard-action) | Fail the build when the window is empty | GitHub Action |
| [pqc-dos-embedded](https://github.com/nickharris808/pqc-dos-embedded) | 169 lines of C: the failure on a real 64 KB device | source |
| [farkas-check](https://github.com/nickharris808/farkas-check) | Re-verify the bound on-device, no SMT solver | source |
| [pqc-migration-mcp](https://github.com/nickharris808/pqc-migration-mcp) | Six MCP tools for AI agents | PyPI |
| [pqc-mfb](https://github.com/nickharris808/pqc-mfb) | 322 cases · 39 failure families · scorer | PyPI |
| [pqc-mfb (data)](https://huggingface.co/datasets/nickh007/pqc-mfb) | The benchmark as a dataset | HF |
| [pqc-formal-corpus](https://huggingface.co/datasets/nickh007/pqc-formal-corpus) | 122 named formal results, 6 provers | HF |
| [pqc-explorer](https://huggingface.co/spaces/nickh007/pqc-explorer) | Try it in your browser, no install | HF Space |

**Start here:** [`pqc-sizes`](https://github.com/nickharris808/pqc-sizes) tells you in five seconds whether your credential fragments and whether a safe cap exists. [`pqc-explorer`](https://huggingface.co/spaces/nickh007/pqc-explorer) does the same in a browser.

### The closed core

Closing the 39 failure families — downgrade binding, retransmission-safe installation, fragmentation transcripts, roaming forward secrecy, multi-link key separation, admission control, group-key binding — is a separate proprietary codebase. Relevant subject matter is covered by a filed provisional patent application.

That split is measured, not asserted: under a replicate noise control only **4 of 32** repair mechanisms are externally distinguishable, so publishing these detectors does not disclose the repairs.

For commercial licensing, open a [GitHub Discussion](https://github.com/nickharris808/pqc-sizes/discussions) or an issue on any of these repos.

## License

Apache-2.0. See [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md).
