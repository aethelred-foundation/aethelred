# M42 × Aethelred — AI Compute Assurance Pilot
## Statement of Work (SOW) — for use under an MSA

**Term:** 10–12 weeks · **Structure:** fixed fee, milestone‑based, phase‑gated · **Location:** M42‑controlled compute environment

This SOW governs the paid pilot. Strategic partnership language (MOU) and any investment discussion are **separate instruments** (see §6). Numerical acceptance thresholds are **agreed at the end of Phase 0/1, after baseline measurement** — this SOW does not assert thresholds before a baseline exists.

---

## 1. Objective

Deploy Aethelred inside an M42‑controlled environment and demonstrate, for selected workloads, an independently verifiable evidence trail linking **approved workload → approved environment → approved model → measured compute → measured energy → known cost**, without sensitive data leaving M42's control — and produce a production scale‑up business case.

## 2. Phases, deliverables, and exit gates

| Phase | Timing | Aethelred deliverables | M42 inputs | Exit gate |
|---|---:|---|---|---|
| **0 — Joint design & governance** | Wk 1 | Architecture & data‑flow diagram; **claim register**; threat model; measurement protocol; responsibilities (RACI) matrix; acceptance plan; DPIA support pack & processing‑role matrix | Workload owner; infra owner; security/privacy reps | Written approval of scope & control boundaries |
| **1 — Deployment & baseline** | Wk 2–3 | Deployment inside M42 boundary; canonical evidence‑record generation; existing cost/performance baseline | One compute environment + representative non‑sensitive workload | **Stop/go:** M42 independently verifies a record with the standalone tool |
| **2 — Live attestation & measurement** | Wk 4–6 | Live vendor‑root attestation (full acceptance protocol); calibrated accelerator/PDU energy measurement; cost attribution | Hardware access; power telemetry; approved cost factors | Attestation + energy reconciliation pass |
| **3 — Real‑world shadow validation** | Wk 7–9 | Instrument one real workload **without affecting clinical decisions**; reproducible evidence + overhead analysis | De‑identified/governed data; workload operator; clinical/technical reviewer | Pre‑agreed technical & operational criteria pass |
| **4 — Decision & scale plan** | Wk 10–12 | Joint technical report; optimization findings; control mapping; implementation runbook; production architecture; financial model | Executive steering review | Production go/no‑go decision |

## 3. M42 dependencies (not success criteria)

The live silicon quote, power telemetry, and governed data are **M42 dependencies / pilot inputs**, not Aethelred deliverables and not the definition of success. Success criteria describe what Aethelred delivers **after** receiving them.

> **Contingency clause:** where an M42 dependency is delayed, the related milestone moves or uses the agreed contingency workload; **the pilot is not deemed failed because a customer dependency was unavailable.**

## 4. Acceptance criteria (decision‑grade; thresholds set after baseline)

| Area | Criterion |
|---|---|
| **Data sovereignty** | No raw patient data, model weights, or identifiable input leaves the approved M42 environment; telemetry & evidence fields documented and inspected |
| **Independent verification** | An M42 engineer verifies records with a standalone tool, no Aethelred hosted service |
| **Hardware trust** | Live quote validated against **production vendor collateral** with freshness, revocation, TCB, policy, and key‑binding controls |
| **Energy accuracy** | Job‑attributable energy reconciles to the agreed ground‑truth instrument within a jointly defined tolerance |
| **Cost accuracy** | Unit cost reproducible from approved input rates; reconciles with M42 infrastructure/finance data |
| **Performance overhead** | Added latency, throughput reduction, storage, and network cost below a threshold set after baseline |
| **Tamper resistance** | Pre‑agreed attacks — substituted model, altered output, replay, stale attestation, modified cost factor, mismatched workload — are rejected, **re‑run by an M42 engineer** |
| **Operational usability** | M42 receives runbook, monitoring approach, failure handling, key‑rotation approach, and a named support process |
| **Business case** | Credible production use case, annual workload volume, value drivers, costs, and a mutually agreed scale decision |
| **Clinical boundary** | No claim of clinical efficacy unless a separate clinician‑approved protocol is completed |

## 5. Pricing & commercial protections

- **Fixed fee: USD 200,000**, paid against milestones (Phase 0/1, Phase 2, Phase 3/4) — **not** in full at kickoff.
- **Stop/go gate after deployment (Phase 1):** if Aethelred cannot operate in‑environment or produce independently verifiable evidence, M42 may terminate before later milestones.
- **Pilot‑fee credit** toward a production agreement above an agreed minimum, signed within a defined period.
- **12‑month price protection** for the first production deployment.
- **Founding design‑partner status** (quarterly roadmap participation, priority access).
- **No blanket exclusivity** (any exclusivity narrow by geography/use‑case/platform/time, with a matching commitment).
- **No surprise integration fee** for the exact pilot‑to‑production path in the final architecture.
- **Exit package** even without expansion: baseline data, verification tooling, measurement methodology, findings, final report.

## 6. Separation of roles

| M42 role | Instrument | M42 commits | Aethelred receives |
|---|---|---|---|
| Paid client | MSA/SOW | Fee, access, named team, approved environment | Revenue + real‑world deployment |
| Founding design partner | Collaboration schedule / MOU | Structured feedback & steering | Roadmap validation |
| Technical validator | Pre‑agreed protocol + post‑pilot statement | Objective review **only after** criteria pass | Permission to use exact approved wording (below) |
| Potential investor | Separate strategic process | No commitment inside this SOW | Optional post‑milestone conversation |

**Approved validation wording (conditional on acceptance):**
> "Aethelred was deployed in an M42‑controlled environment and passed the jointly agreed protocol for [specific capabilities]."

Avoid "M42‑certified", "M42‑approved", or any claim that M42 validated the entire technology or clinical efficacy. If M42 also invests, technical and investment decisions are made by **separate groups** to preserve validation independence.

## 7. Structural ROI model (built during the pilot, on M42 baselines)

`Annual compute savings = workload volume × (verified baseline unit cost − optimized unit cost)` · `Capacity benefit = recoverable GPU‑hours × internal value/GPU‑hour` · `Audit productivity = reviewed runs × review time saved × loaded labor cost` · `Sustainability reporting benefit = measured workloads × manual measurement/reporting effort avoided` · `Risk value = jointly accepted incident‑probability reduction × expected incident cost`.

*Numbers are not asserted; M42 baseline metrics are an early Phase‑0/1 discovery requirement.*
