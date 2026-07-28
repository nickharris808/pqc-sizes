# pqc-sizes

[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://pypi.org/project/pqc-sizes/)
[![tests](https://img.shields.io/badge/tests-88%20passing-brightgreen.svg)](tests/)
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

**📖 Full documentation, tutorial and conceptual guide: <https://nickharris808.github.io/pqc-toolkit/>**

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
pip install git+https://github.com/nickharris808/pqc-sizes
```

Zero dependencies, Python 3.9+. Not on PyPI yet, so `pip install pqc-sizes`
does not work today — the command above does.

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

### Sizing a budget from scratch

`window` answers "is my budget enough?". Most people start a step earlier — they
have a credential and a concurrency target and need the budget:

```
$ pqc-sizes budget --kem ML-KEM-768 --sig ML-DSA-65 --concurrency 4
ML-KEM-768 + ML-DSA-65: 7,533 B, 4 concurrent contexts
  minimum budget   30,132 B
  at exactly this budget the window is a single point (7,533 B): the only
  admissible cap is the object size itself, leaving no headroom for a larger
  legitimate object.

  2x headroom      60,264 B
  4x headroom      120,528 B
```

The minimum is exact in both directions — a test asserts that budget produces a
non-empty window and that one byte less does not.

### SARIF for GitHub code scanning

`--format sarif` emits a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json)
log so an empty window appears in the repository's Security tab, anchored to the
config file that causes it. A test validates the output against the published
schema, because GitHub silently ignores a SARIF file it cannot parse.

```yaml
- run: pqc-sizes check pqc.json --format sarif -o pqc.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: pqc.sarif }
```

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
pip install -e ".[dev]" && pytest    # 88 passed
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

## CLI reference

| Command | What it does | Exit |
|---|---|---|
| `pqc-sizes sizes [--kind KEM\|signature]` | The algorithm table | 0 |
| `pqc-sizes credential --kem K --sig S` | Credential bytes, component by component | 0 |
| `pqc-sizes fragments TRANSPORT --kem K --sig S` | Fragment count on a transport | 0 |
| `pqc-sizes fragments TRANSPORT --bytes N` | Same, for a raw object size | 0 |
| `pqc-sizes window --largest-object N --budget N --concurrency N` | Does a safe cap exist? | 0 / **1** |
| `pqc-sizes sweep --largest-object N --budget N --max-concurrency N` | Where the window collapses | 0 |
| `pqc-sizes budget --kem K --sig S --concurrency N` | How much memory do N contexts need? | 0 |
| `pqc-sizes check CONFIG` | Gate on a committed JSON/YAML config | 0 / **1** |
| `pqc-sizes check CONFIG --format sarif` | Same, as a GitHub code-scanning report | 0 / **1** |

`--json` is **global** and goes before the subcommand:
`pqc-sizes --json window ...`. The exit code carries the verdict in `--json`
mode too, so you can pipe to `jq` and branch on `$?`.

**Config keys** for `check`: `kem`, `sig`, `largest_object`, `budget`,
`concurrency`, `transport`. Give either `largest_object`, or both `kem` and
`sig`. An unrecognised key is an error rather than being ignored — a silently
dropped setting is a config that does not do what its author thinks.

## Troubleshooting

**`EMPTY WINDOW` and I think my config is fine.** That is the tool working. It
means no single cap is both ≥ your largest legitimate object and ≤ budget ÷
concurrency. The message gives you three numbers, any one of which fixes it.

**Exit code 1 vs 2.** `1` means the check ran and the answer is bad. `2` means
the invocation was wrong. If CI reports `2`, read stderr — every validation
error names the flag to change.

**`unrecognized arguments: --json`.** It is a global flag; put it before the
subcommand.

**`unknown transport '...'`.** Run `pqc-sizes fragments --help`, or pass a raw
byte count instead of a name.

**Numbers differ from my build.** These are published parameter-set sizes.
Certificate chains, encodings and framing are yours to add — pass the real total
via `--bytes` or `largest_object`.

## Honest scope

**What this proves.** That your *configuration* admits a reassembly cap which is
both feasible (at least as large as the biggest legitimate object) and safe (no
larger than budget ÷ concurrency). The arithmetic is exact — Python integers, no
floating point — over published object sizes.

**What it does NOT prove.**

- **Not that your code enforces the cap.** This never sees your implementation. A
  non-empty window means a safe cap *exists*, not that anything applies it.
- **Not that the sizes match your build.** They are the published parameter-set
  sizes. Encodings, certificate chains and framing overhead are yours to add.
- **Not a security review.** Fragmentation exposure is one failure family of 39;
  see [`pqc-mfb`](https://github.com/nickharris808/pqc-mfb) for the other 38.
- **Not a cryptographic claim.** No key exchange, no signature, no randomness —
  it is arithmetic.

**Exit codes.** `0` a safe cap exists · `1` the window is empty · `2` bad usage.
That split is deliberate: a CI gate must tell "your design is unsafe" apart from
"you typed the flag wrong".

---

## The PQC migration toolkit

Eleven free tools for teams moving authenticated key exchange to post-quantum. They **find and measure**; they do not repair.

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
| [pqc-bounds-lean](https://github.com/nickharris808/pqc-bounds-lean) | The same bound in Lean 4 — 0 `sorry`, 0 imports | source |
| [pqc-dos-gate-rtl](https://github.com/nickharris808/pqc-dos-gate-rtl) | The gate in synthesizable RTL, 5 Yosys proofs | source |
| [pqc-explorer](https://huggingface.co/spaces/nickh007/pqc-explorer) | Try it in your browser, no install | HF Space |

**New here?** The [end-to-end tutorial](https://github.com/nickharris808/pqc-sizes/blob/main/TUTORIAL.md) walks one realistic migration through all of them in about ten minutes: sizes -> window -> CI gate -> benchmark.

**In a hurry?** [`pqc-sizes`](https://github.com/nickharris808/pqc-sizes) tells you in five seconds whether your credential fragments and whether a safe cap exists. [`pqc-explorer`](https://huggingface.co/spaces/nickh007/pqc-explorer) does the same in a browser, with no install.

### The closed core

Closing the 39 failure families — downgrade binding, retransmission-safe installation, fragmentation transcripts, roaming forward secrecy, multi-link key separation, admission control, group-key binding — is a separate proprietary codebase. Relevant subject matter is covered by a filed provisional patent application.

That split is measured, not asserted: under a replicate noise control only **4 of 32** repair mechanisms are externally distinguishable, so publishing these detectors does not disclose the repairs.

For commercial licensing, open a [GitHub Discussion](https://github.com/nickharris808/pqc-sizes/discussions) or an issue on any of these repos.

## License

Apache-2.0. See [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md).
