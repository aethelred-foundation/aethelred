# Target Selection — One Platform, One Workload (Pilot Focus)

Per the consultant's non‑negotiable #10: choose a single target attestation platform and a single day‑one workload, with a named flagship and a named expansion. Depth over breadth.

## Attestation platform: **AMD SEV‑SNP** (primary)

| | |
|---|---|
| **Why** | Direct hardware‑quote verification (strongest trust story); our most complete verifier (1184‑byte report, ECDSA‑P384, VCEK→ASK→ARK X.509); widely available in confidential‑VM offerings across clouds. |
| **Pilot deliverable** | Validate a **live SEV‑SNP quote** against AMD's production root collateral, with the full acceptance protocol (freshness, revocation, TCB policy, debug‑reject, measurement policy, key‑binding, replay protection). |
| **Fallbacks kept warm** | The other five adapters (AWS Nitro, Intel TDX, Azure MAA, GCP Confidential Space, NVIDIA) remain implemented; a second platform is added only if M42's environment requires it. |

## Workloads: day‑one → flagship → expansion

| Stage | Workload | Data risk | Proves |
|---|---|---|---|
| **Day‑one gate** | An **M42‑owned non‑patient / low‑risk inference job** (e.g. a Med42 evaluation run) | None | Deployment, live attestation, model/container provenance, cost + energy measurement, independent verification — **before** any data‑governance approvals |
| **Flagship** | **Digital pathology in shadow mode** | De‑identified / governed; processed in place | The assurance layer around an **existing** clinical AI workflow (no effect on clinical decisions), with reproducible evidence + overhead analysis |
| **Expansion** | **Genomics** | Higher governance friction | The production expansion story **after** the assurance layer is proven on a lower‑friction workload |

## Rationale (one line)

Prove the compute‑assurance layer **deeply on one platform and one real M42‑relevant workflow**, start before patient‑data approvals so privacy sign‑off does not consume the pilot, and expand into genomics once the pattern is established.
