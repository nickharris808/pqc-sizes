# Tutorial — from "we're adding ML-KEM" to a gated build

A worked end-to-end path through the toolkit, using one running example. Every
command here is executed by
[`tools/check_readme_examples.py`](https://github.com/nickharris808/pqc-sizes), so the
output shown is what you get.

**The scenario.** You maintain an 802.11 supplicant. Someone has asked for a
post-quantum handshake: ML-KEM-768 for key establishment, ML-DSA-65 for
authentication. Your reassembly buffer is 64 KiB and you expect at most 4
simultaneous handshakes.

Five steps, about ten minutes.

---

## 1. How big is the credential, really?

```bash
pip install git+https://github.com/nickharris808/pqc-sizes
```

```
$ pqc-sizes credential --kem ML-KEM-768 --sig ML-DSA-65
credential: ML-KEM-768 + ML-DSA-65
  ML-KEM-768 public key                  1,184 B
  ML-KEM-768 ciphertext                  1,088 B
  ML-DSA-65 public key                   1,952 B
  ML-DSA-65 signature                    3,309 B
  TOTAL                                  7,533 B
```

An X25519 share is 32 bytes. This is **7,533** — 235× larger, and that is the
whole story. Everything below follows from it.

## 2. Does it still fit in a frame?

```
$ pqc-sizes fragments wifi-mgmt-frag --kem ML-KEM-768 --sig ML-DSA-65
ML-KEM-768+ML-DSA-65 credential over wifi-mgmt-frag (384 B/frame): 20 fragments
  -> fragmentation is mandatory; the receiver holds partial, unauthenticated
     state across 20 frames
```

No. It becomes **20 fragments**, and the second line is the part that matters:
your receiver now holds attacker-influenced partial state *before* it can
authenticate any of it. You need a cap on reassembly memory.

## 3. Does a safe cap exist?

A cap has two boundaries, not one:

- **floor** — the largest legitimate object you must accept, or you break honest peers.
- **ceiling** — your memory budget ÷ worst-case concurrency, or concurrent sessions exhaust you.

At 64 KiB and 4 contexts:

```
$ pqc-sizes window --largest-object 7533 --budget 65536 --concurrency 4
window [7,533, 16,384] B; recommended cap 16,384 B (budget 65,536 B / 4
concurrent contexts)
  max safe concurrency at this object size: 8
```

Fine — cap at 16,384 B, and you have headroom to 8 contexts.

Now suppose product asks for a hash-based signature instead:

```
$ pqc-sizes window --largest-object 19392 --budget 65536 --concurrency 4
EMPTY WINDOW: floor 19,392 B > ceiling 16,384 B (short by 3,008 B). No
capacity cap is both feasible and safe. Raise the budget to at least 77,568 B,
reduce concurrency to at most 3, or choose a smaller credential.
```

**No cap works at all.** Not "pick carefully" — the interval is empty. That is a
design answer, available before anyone writes code, and the tool gives you the
three numbers that would fix it.

## 4. Put it in CI

Commit the parameters instead of retyping flags. Two runnable configs ship in
[`examples/`](examples); `examples/pqc.json` is:

```json
{
  "kem": "ML-KEM-768",
  "sig": "ML-DSA-65",
  "budget": 65536,
  "concurrency": 4
}
```

```
$ pqc-sizes check examples/pqc.json
examples/pqc.json: 7,533 B object, 65,536 B budget, 4 contexts
  window [7,533, 16,384] B; recommended cap 16,384 B (budget 65,536 B / 4
  concurrent contexts)
  max safe concurrency at this object size: 8
```

`examples/pqc-empty-window.json` is the same deployment with a hash-based
signature, and exits 1:

```
$ pqc-sizes check examples/pqc-empty-window.json
examples/pqc-empty-window.json: 19,392 B object, 65,536 B budget, 4 contexts
  EMPTY WINDOW: floor 19,392 B > ceiling 16,384 B (short by 3,008 B). No
  capacity cap is both feasible and safe. Raise the budget to at least 77,568
  B, reduce concurrency to at most 3, or choose a smaller credential.
```

Exit code is **0** when a cap exists and **1** when the window is empty, so it
gates a build as-is. In GitHub Actions, use
[`pqc-guard-action`](https://github.com/nickharris808/pqc-guard-action):

```yaml
- uses: nickharris808/pqc-guard-action@v1
  with:
    kem: ML-KEM-768
    sig: ML-DSA-65
    budget: "65536"
    concurrency: "4"
```

## 5. Memory exhaustion is 1 of 39 failure families

Sizing tells you the buffer is safe. It says nothing about downgrade binding,
key reinstallation, fragment splicing, or roaming forward secrecy — all of which
the size change reopens. [`pqc-mfb`](https://github.com/nickharris808/pqc-mfb)
enumerates 39 families over 322 executed cases.

```bash
pip install git+https://github.com/nickharris808/pqc-mfb
pqc-mfb submit -o results.json      # all 322 case ids, pre-filled
```

Edit the ones your implementation holds, then:

```bash
pqc-mfb score results.json
```

The scaffold starts at the documented floor — 0% coverage, no regressions — so
your first run is green and you raise coverage from there. To understand any
family:

```
$ pqc-mfb explain fragment_splice
```

Two rules worth knowing before you submit:

- **Silence is not credit.** An unanswered case makes the verdict `INCOMPLETE`
  (exit 3), never `PASS`.
- **Regressions are a hard fail.** Ten cases pass even unrepaired; breaking one
  is `FAIL` (exit 1) no matter how high your coverage.

## Where to go next

| If you want to… | Use |
|---|---|
| See the failure on real silicon | [`pqc-dos-embedded`](https://github.com/nickharris808/pqc-dos-embedded) — 169 lines of C under QEMU |
| Re-verify the bound yourself, on-device | [`farkas-check`](https://github.com/nickharris808/farkas-check) — integer C, no solver |
| Let an AI agent do this | [`pqc-migration-mcp`](https://github.com/nickharris808/pqc-migration-mcp) — six MCP tools |
| Try it with no install | [`pqc-explorer`](https://huggingface.co/spaces/nickh007/pqc-explorer) |
| Work in JS | [`pqc-sizes-js`](https://github.com/nickharris808/pqc-sizes-js) |

## What you have, and have not, established

After all five steps you know that **your configuration admits a safe cap**, and
which of 39 modelled failure families your implementation closes.

You have **not** established that your code enforces the cap, that your
implementation matches the model, or that the 39 families are exhaustive for
your protocol. Those are different questions, and no tool here answers them.
See each README's *Honest scope* section.
