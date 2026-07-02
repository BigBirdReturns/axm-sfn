# Endstates and the 30-Year Durability Plan

**Status:** living document, Track 2 input
**Scope:** the whole AXM SFN stack — edge daemon, spoke, shard format, trust
model, and the certification standard it anchors
**Horizon:** 2026–2056

---

## Why this document exists

axm-sfn's stated purpose is not "sign 3D prints." It is to make process
custody *portable*, so that qualification attaches to a part's verifiable
fabrication record instead of to a facility's paperwork. That is the
mechanism by which industrial capability can decentralize: today,
qualification cost is the moat that concentrates aerospace, defense, and
medical manufacturing in a handful of giant qualified suppliers. If a sealed
shard can carry the burden of proof that a facility audit carries today,
then ten thousand small shops can bid on work currently locked to primes.

That only works if the system survives long enough to be trusted, and stays
decentralized while it grows. A part qualified in 2030 may fly, drive, or be
implanted until 2060. The custody record must remain verifiable — and
verifiable *by anyone, without permission* — for that entire span. So the
durability question and the anti-centralization question are the same
question, and this document treats them together.

Method: enumerate the endstates, identify which design decisions select
between them, and derive the invariants and the phased plan.

---

## Part 1 — Endstates

Seven endstates, from best to worst. The plan in Part 3 exists to steer
toward E1 and to make E2–E7 structurally difficult.

### E1. Open substrate ("TCP/IP of fabrication provenance")

The shard format and verifier are a boring, frozen public standard.
Thousands of independent operators run nodes; multiple independent
certifying bodies exist (the NRTL model — UL, Intertek, CSA — applied to
fabrication custody); regulators accept sealed shards as qualification
evidence; MPF profiles are a public commons of codified process knowledge.
No single entity can deny anyone the ability to seal, verify, or certify.
Verification of a 2026 shard on 2056 hardware works from the published spec
alone.

**What selects for it:** frozen format + offline verification + plural trust
roots + copyleft kernel + a spec that outlives every implementation.

### E2. Captured standard

The code stays open, but one entity — a defense prime, a hyperscaler, or
even the AXM Foundation itself — becomes the *mandatory* trust root: the
only signer of MPF profiles, the only accepted certifier, or the only shard
registry regulators recognize. Verification is open; *permission* is not.
This is hypercentralization through the trust store rather than the code,
and it is the most likely bad ending because it can happen with everyone's
best intentions ("just use the Foundation's key for now").

**Warning signs:** a single MPF signing key; a certification README that
names one approved-vendor-list operator; shard verification that phones
home; a CLA that lets one org relicense.

### E3. Ghettoized niche

The prosumer/Voron community adopts it; industry does not. OEMs of
industrial machines ship proprietary, machine-locked provenance instead, and
regulators standardize on that. axm-sfn survives as a hobbyist curiosity
while actual industrial capability re-centralizes around OEM ecosystems.

**Warning sign:** the Machine Adapter surface stays Moonraker-only. Klipper
printers are the beachhead, not the territory.

### E4. Regulatory conscription

Government mandates custody records — but mandates them *through* a central
registry, with identity escrow and revocation. Sovereign nodes become
surveilled nodes; the "sovereign" in Sovereign Fabrication Node inverts.
This endstate arrives disguised as E1 (adoption!) and is distinguishable
from it only by whether INV-D1 and INV-D2 (below) still hold.

### E5. Bitrot death

axm-core goes unmaintained; the spoke never gets verified end-to-end (it is
*currently* in this state — see Track 1.5); Moonraker's API drifts; TPM 2.0
hardware ages out; the project dies quietly. Sealed shards become
unverifiable artifacts within 15 years — cryptographically perfect,
practically meaningless.

### E6. Cryptographic decay

The TPM's RSA-PSS signatures fall to quantum cryptanalysis somewhere in the
2035–2045 window (CNSA 2.0 already schedules RSA's retirement by ~2033 for
national security systems). If nothing is done beforehand, every historical
custody claim becomes forgeable-in-retrospect and the archive's evidentiary
value collapses. Note: BLAKE3 and ML-DSA-44 are not the weak links here;
the TPM's classical signature is.

### E7. Fork fragmentation

Governance failure produces incompatible forks that each call their output
"sealed AXM shards." Verifiers disagree; regulators walk away; the network
effect that makes provenance valuable dissolves. (Distinguish this from
*healthy* forking, which INV-D6 guarantees: a compliant fork that verifies
the same shards is a safety valve, not fragmentation.)

---

## Part 2 — What the current architecture already gets right, and where it is exposed

An honest audit of the stack as it exists in this repo.

### Assets (things to freeze and defend)

1. **The frozen Genesis kernel + AXLF/AXLR v1 format.** One continuity
   verifier for every spoke, hardcoded format, no spoke-specific verifier
   (docs/STREAM_FORMAT.md). This is the single most durable design decision
   in the project: it means the verification surface is small enough to
   specify completely, reimplement independently, and never grow. The
   format's arithmetic is sound for the horizon — `frame_id` is uint32 at
   1 Hz, so a single session can run ~136 years before overflow.

2. **Sealed-before-break archival validity (designed, not yet delivered).**
   The shard seal is ML-DSA-44 (FIPS 204, post-quantum). If the TPM's
   RSA-PSS packet signatures are *contained inside* the PQ-sealed shard,
   an RSA break in 2040 does not forge a shard sealed in 2026: the PQ seal
   is a cryptographic time capsule over the classical signatures. This is
   the entire answer to E6 for the historical archive — but note carefully:
   **the current compile path does not yet deliver it.** The TPM
   signatures, quotes, and keys stay behind in the hot buffer (see
   Exposure 5a and Part 3½). The architecture makes the property cheap to
   deliver; delivering it is a now-item, not a Phase 3 item.

3. **Offline, local-first custody.** The hot buffer is SQLite WAL on the
   node; sealing is local; the uploader is optional and explicitly *not*
   the seal. SQLite is arguably the safest 30-year dependency in software
   (its file format is a US Library of Congress recommended storage
   format). Nothing in the seal path requires a network.

4. **AGPL-3.0.** Network use triggers disclosure; proprietary forking by
   primes or integrators is blocked. This is the license doing
   anti-capture work.

5. **Non-selective recording (REQ 5).** The custody clock ticks whether or
   not the printer talks; silence is recorded, gaps are
   `E_BUFFER_DISCONTINUITY`. Selective recording is the root exploit of
   every paper-based quality system; closing it at the clock level is what
   makes the record worth carrying for 30 years.

### Exposures (ranked by how quickly they select a bad endstate)

1. **The MPF trust store is TBD** (README, Open Questions). This is the E2
   capture vector, full stop. Whoever signs Material-Process Profiles
   decides who gets certified. Until it is federated, the project carries a
   single-root design in its most consequential slot.

2. **The spoke has never run against a live axm-core** (Track 1.5). The
   only path to a sealed shard is unverified. Until this closes, the
   project's durability claim is theoretical and E5 is the default
   trajectory.

3. **axm-core is a single implementation dependency.** `compile_generic_shard`
   call shapes are taken from an API spec. If axm-core stalls, the seal
   path stalls. The shard format needs a specification independent of the
   implementation, and eventually a second implementation.

4. **Moonraker/Klipper coupling.** Community-maintained, 3D-printing-
   specific, unlikely to exist in recognizable form in 2056 — and
   irrelevant to CNC, welding, casting, and composite layup, which is where
   "real industrial capability" lives. The daemon's custody loop, hot
   buffer, and policy engine are already machine-agnostic; the Moonraker
   client is an adapter that hasn't been named as one yet.

5a. **Attestation evidence never reaches the sealed shard.** The AXLR
   payload carries the BLAKE3 chain link, the SHA-256 digest, a verdict
   byte, a `tpm_present` flag, and the sequence number — not the TPM
   signature itself. The journal text records `quoted=true/false`, not
   signature bytes. The signatures, the quotes (PCR measurements), the AK
   public key, and the EK certificate chain all remain in `buffer.db`,
   which is a *hot* buffer and will be pruned. A verifier holding only a
   sealed shard can verify the BLAKE3 chain and the ML-DSA seal but cannot
   verify a single TPM signature; once the buffer is gone, the
   hardware-attestation claim is unverifiable forever. This is the gap
   between Asset 2's design and its delivery, and it is the highest-
   priority format fix in the project (Part 3½, item 1).

5. **Software-only degradation is invisible in the record.** When
   `/dev/tpmrm0` is absent, packets are chained but not TPM-signed. Graceful
   degradation is correct; *silent* degradation is not. A 2040 verifier
   must be able to distinguish attestation levels from the sealed record
   itself, or unattested shards will trade at attested value until the
   first scandal reprices the entire archive.

6. **TPM 2.0 hardware and vendor concentration.** ~10-year hardware
   half-lives; a small set of vendors (Infineon, ST, Nuvoton); RSA-PSS
   default; PQ algorithms only now entering TCG specs. The attestation
   root needs an abstraction (TPM 2.0 today; DICE, PQ-TPM, or successors
   tomorrow) and a recorded `attestation_class` per session.

7. **Bus factor and identity.** One repo, one maintainer org, one domain
   (axm.tools). None of these should be load-bearing for verification in
   ten years.

---

## Part 3 — The Durability Invariants

Six invariants. Every future design decision, Track 2 artifact, and
governance rule gets tested against these. A change that violates one is a
different project wearing this one's name.

- **INV-D1 — Permissionless verification.** Verifying any sealed shard
  requires no network, no account, no fee, and no permission — forever.
  The verifier ships with the spec.

- **INV-D2 — No mandatory intermediary.** No single entity may ever be a
  required party for sealing, verifying, certifying, or distributing
  shards. Every trust role (MPF signing, certification, transparency
  logging) must support at least two independent operators, and the
  protocol must not distinguish a "primary."

- **INV-D3 — Spec-sufficient verifiability.** Every sealed shard remains
  verifiable from the published specification plus public test vectors
  alone, on commodity hardware, without any code from this repo. The spec
  is authoritative; implementations are disposable.

- **INV-D4 — Crypto-agility with sealed-before-break validity.** Every
  signature and hash in the stack carries an algorithm identifier; the
  system can dual-sign across migrations; and a shard sealed before an
  algorithm's public break retains full evidentiary standing via its outer
  seal and re-anchoring (see Phase 3).

- **INV-D5 — Degradation is recorded, never hidden.** Every reduction in
  assurance (software-only signing, missing quotes, provenance faults,
  buffer discontinuities) is embedded in the sealed record and surfaced by
  the verifier. The system may degrade; the *record* of degradation may
  not.

- **INV-D6 — Fork-off rights.** License (AGPL-3.0, no relicensing-capable
  CLA — DCO only), published spec, and public test vectors together
  guarantee that a compliant fork can always exist and always verify the
  same historical shards. This is the ultimate check on every other
  governance failure.

---

## Part 4 — The 30-year plan, phased

Each phase has exit criteria. Phases are gates, not dates; the years are
planning anchors.

### Phase 0 — Prove the seal (now → +1 year)

The project is currently in endstate E5's basin of attraction. Leave it.

- [ ] Run the spoke end-to-end against a live `axm-core@v1.1.0` install;
      confirm `compile_generic_shard` call shapes; seal and self-verify a
      real session. (Track 1.5's open box.)
- [ ] Add `attestation_class` to the custody record so software-only mode
      is distinguishable inside the sealed shard (INV-D5).
- [ ] Land the shard-content enablers from Part 3½ (attestation evidence
      into the shard, algorithm/key identifiers, spec-verifiable
      preimages) **before** generating the golden corpus below — test
      vectors frozen around the current gap would canonize it.
- [ ] Publish **SHARD-SPEC v1**: the AXLF/AXLR container (already in
      docs/STREAM_FORMAT.md), the 256-byte CustodyPacket payload layout,
      the BLAKE3 chaining rule, the segment Merkle rule, and the shard
      envelope — as a standalone normative document with a public test
      vector corpus (valid shards, every failure class including
      `E_BUFFER_DISCONTINUITY`, truncation, reordering, bad signatures).
- [ ] Archive the repo and spec in Software Heritage and at least one
      other independent archive. Reproducible, pinned builds (Go toolchain
      + vendored deps) so a future auditor can rebuild today's binaries.

**Exit criterion:** a stranger seals a session on their own printer and
verifies it offline using only published artifacts.

### Phase 1 — Break the beachhead's walls (+1 → +3 years)

Aim directly at E3.

- [ ] Extract the **Machine Adapter Interface**: the Moonraker client
      becomes the first adapter behind a formal boundary (state cache in,
      custody ticks out). Second adapter targets industrial reality —
      OPC-UA or LinuxCNC — because CNC subtractive is where qualification
      pain and dollars actually are. The 1 Hz custody clock, hot buffer,
      TPM worker, and policy engine do not change.
- [ ] **Second verifier implementation** in a different language, by a
      different author, from SHARD-SPEC v1 alone (INV-D3's proof). Where
      the implementations disagree, the spec was wrong; fix the spec.
- [ ] MPF schema v1 + the **federated trust store**: MPF profiles carry
      multiple signatures from independent signers; a node's config lists
      which signers it accepts (like CA bundles, but plural by protocol —
      INV-D2). No Foundation master key. Threshold or multi-sig escrow are
      acceptable *implementations of a signer*, never a substitute for
      plural signers.
- [ ] Governance charter: DCO-only contributions, kernel-freeze
      constitutionalized (format changes require a new version, never a
      mutation of v1), no single funder above a fixed share, and explicit
      INV-D6 language.

**Exit criterion:** two machine classes, two verifiers, two independent MPF
signers, zero mandatory intermediaries.

### Phase 2 — The certification commons (+3 → +8 years)

Aim directly at E1's adoption mechanism and E2/E4's prevention.

- [ ] Stand up the NRTL-analogue: multiple independent certification
      bodies that audit *MPF profiles and node provisioning practices*,
      not facilities. America already runs safety certification this way
      (OSHA recognizes many NRTLs; ASTM and ANSI are private, plural
      standards bodies); fabrication custody should ride the same
      institutional pattern, and it is the pattern regulators already
      know how to trust.
- [ ] Optional, plural **transparency logs** (Certificate-Transparency
      style: many logs, gossip between them, no single log required) for
      shard digests. Logs add discoverability and anti-rollback; they must
      never become a verification dependency (INV-D1).
- [ ] Regulatory engagement with the sealed-shard-as-evidence framing:
      DoD/DLA additive (battle-damage repair and forward fabrication are
      the natural first customers for portable custody), then FAA/FDA
      pathways. The red line in every engagement: mandates may *require*
      shards; they may not require a *registry* (E4). If a mandate demands
      identity escrow or central revocation, the correct answer is the
      published spec's answer, not a quiet protocol change.
- [ ] MPF profile commons: a public, versioned, multi-signed library of
      material-process profiles. This is Layer 1 — the place where
      industrial process knowledge accumulates *in the open* instead of
      inside primes. Treat its openness as seriously as the code's.

**Exit criterion:** a part qualified via sealed shards + certified MPF is
accepted by at least one regulator or major buyer, certified by a body the
Foundation does not control.

### Phase 3 — Cryptographic succession (+5 → +15 years, overlapping)

Aim directly at E6. Calendar-driven, not adoption-driven.

- [ ] **Attestation-root migration:** TCG is adding PQ algorithms to TPM
      specs; as PQ-capable roots of trust ship, new provisioning uses them
      and the `attestation_class` field records which root signed. RSA-PSS
      provisioning gets a published sunset date aligned with CNSA 2.0
      (~2033).
- [ ] **Seal upgrade path:** ML-DSA-44 is NIST category 2 — adequate now,
      thin for a 30-year archive. Define the reseal operation (a new shard
      that contains and re-signs an old shard, ML-DSA-65/87 or SLH-DSA as
      the conservative hash-based fallback) so the archive can be carried
      forward without touching the frozen v1 container.
- [ ] **Re-anchoring program:** on a fixed cadence, publish the Merkle
      root of all known shard digests into multiple independent public
      timestamping venues. After re-anchoring, even a future ML-DSA break
      cannot rewrite pre-break history — forgery would have to beat the
      public timestamps too. This is cheap, boring, and the strongest
      possible answer to "why should a 2056 court believe a 2026 shard?"
- [ ] BLAKE3 needs no action on this horizon; monitor like everything
      else.

**Exit criterion:** every shard ever sealed is covered by at least one
post-quantum seal *and* at least one public re-anchor.

### Phase 4 — Generational transfer (+10 → +30 years)

Aim directly at E5's long tail and E7.

- [ ] **The 30-year verification test**, run annually: take the oldest
      sealed shard in existence, hand SHARD-SPEC v1 and the test vectors
      to an implementer with no project history, and confirm they can
      verify it on current commodity hardware. The year this test fails
      is the year the project has already died; run it so that year never
      arrives silently.
- [ ] Maintainership succession as protocol, not personality: the spec,
      trust-store composition, and archives must survive the Foundation's
      own disappearance. Domain (axm.tools), repo host, and org accounts
      are conveniences; the spec + vectors + plural archives are the
      institution.
- [ ] Format v2 only under duress (a real cryptographic or capacity
      forcing function), and only as a *new* format verified alongside v1
      — v1 verifiers must verify v1 shards forever. The frozen kernel's
      freeze is the promise; keep it.
- [ ] Fragmentation defense (E7): the name "AXM sealed shard" is defined
      by conformance to the public spec and test vectors, not by
      affiliation. A conforming fork is a peer (INV-D6); a non-conforming
      one is simply a different format, and the annual verification test
      plus the plural certifier network make that legible to buyers and
      regulators without anyone owning a trademark cudgel.

**Exit criterion:** the system no longer depends on anyone who built it.

---

## Part 3½ — Phase 3/4 enablers that must land NOW

Phases 3 and 4 are not free-standing future work: each depends on hooks
that must exist in the format and the evidence chain *before* the install
base grows. Format decisions fossilize with adoption — all five items
below are cheap before the first production shard is sealed and become
migration projects afterward. Items 1–3 change what goes into a shard, so
they must land **before** the Phase 0 golden corpus is generated, or the
test vectors freeze around the gap.

### 1. Get the attestation evidence into the shard

The single most urgent item; see Exposure 5a. Add an `ext/attestation@1`
artifact at compile time carrying: per-packet TPM signatures, the quote
records (PCR values and quote signatures), the AK public key, and the EK
certificate chain (including the TPM vendor CA certificates, whose roots
will themselves expire and disappear). The mechanism already exists —
`compile.py`'s pass 2 reseals the Merkle root over everything in the shard
directory including `ext/`, and Genesis ignores `ext/` — so this lands
under the ML-DSA seal with zero changes to the frozen kernel. This one
change makes Asset 2's time-capsule property true.

### 2. Algorithm and key identifiers at every layer

`CustodyPacket.TPMSig` is a bare byte slice — no signature algorithm, no
hash algorithm, no key fingerprint anywhere in the packet or the stream. A
2045 verifier cannot even know what to try. The shard layer already has
suite agility (`suite=SUITE_MLDSA44` is a parameter with an Ed25519
alternative); the packet/TPM layer has none. The AXLR payload's 182
reserved bytes are the budget: allocate `attestation_class`, `sig_alg`,
and a signing-key fingerprint now. Reserved-as-zeros → allocated is a
compatible change today; it stops being one the moment there is an install
base of shards in which zeros are ambiguous.

### 3. Make the signed preimage spec-verifiable

The canonical bytes that `packet_sha256` and the TPM signature cover are
currently defined as "whatever Go's `encoding/json` emits for this struct
in field order." Go's float formatting is not reproducible from a spec by
a 2056 reimplementer — and the preimage (`telemetry_json`) never enters
the shard either, so the SHA-256 in the AXLR payload is unverifiable from
the shard alone. Fix: ship the stored canonical packet bytes into the
shard (an `ext/packets@1` beside the attestation artifact) and define the
rule as **hash-over-stored-bytes**, not hash-over-recomputable-
canonicalization. Stored bytes are the archival-robust definition; a
canonicalization algorithm is a dependency on a compiler's behavior.

### 4. Define reseal authorization semantics

The two-pass reseal in `compile.py` (recompute Merkle root, re-sign
manifest) *is* the Phase 3 reseal primitive in embryo. What is missing is
the semantics: what makes a 2035 reseal with ML-DSA-87 *authorized* rather
than merely re-signed? Required now: a key-succession rule (building on
the delegated-identity work in `axm_sfn_core.ids`, INV-25/27) and a hard
requirement that reseal **retains** the original signature and manifest
rather than replacing them. Cheap to write down today; contentious to
invent mid-migration with an archive at stake.

### 5. Start re-anchoring immediately — not in Phase 3

Re-anchoring only proves seal-time *forward from when it starts*. Every
unanchored year produces shards whose "sealed before the break" claim
rests on a self-asserted `created_at` (currently defaulting to wall
clock). The canonical `shard_id` already exists
(`shard_blake3_<merkle_root>`), so even a crude scheduled job publishing
digest Merkle roots to two independent public timestamping venues starts
the clock. This is the cheapest item on the list and the only one where
delay is strictly irreversible.

---

## Part 5 — The theory of the case, restated

Hypercentralization in manufacturing is not primarily a technology problem;
it is a *trust-cost* problem. Qualification, audit, and liability costs
scale per-facility, so trust pools in a few enormous facilities. This stack
attacks exactly that: it makes the unit of trust the *sealed process
record* instead of the *audited facility*, and it makes that record
verifiable by anyone, offline, for decades.

Every durable decentralized American institution that this plan borrows
from — plural NRTLs, private standards bodies, the IETF's
rough-consensus-and-running-code, Certificate Transparency's many-logs
model — shares one property: **no mandatory intermediary, plus a cheap exit
(fork, competing certifier, competing log) that keeps every incumbent
honest.** The six invariants encode that property; the four phases build
the institutions around it; the endstates are what happens when any one of
them is traded away for convenience.

The frozen kernel was the right first move. The next three moves — prove
the seal (Phase 0), federate the trust store before it ossifies (Phase 1),
and record degradation honestly (INV-D5) — decide which endstate this
becomes.
