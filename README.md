# wsn-secure-routing

A discrete-event Java simulation comparing baseline **LEACH** clustering against a
**hardened, DoS-resilient secure LEACH variant** for wireless sensor networks (WSNs),
built around a real first-order radio energy model and real RSA-1024 / AES-128
cryptography (`java.security` / JCE — no crypto is faked or stubbed out).

It exists to answer one question honestly: **does the security layer actually pay for
itself in energy, and does it actually blunt denial-of-service attacks?** The answer,
measured rather than assumed, is: *it costs a little more energy when the network is
not under attack, and it more than pays that back — and then some — the moment an
attacker shows up.* See [Results](#results) for the real numbers, including where the
secure variant is *worse*.

## Contents

- [The radio energy model](#the-radio-energy-model)
- [Baseline LEACH](#baseline-leach)
- [Secure LEACH](#secure-leach)
- [The Interlock Protocol](#the-interlock-protocol-and-why-it-defeats-a-relay-mitm)
- [DoS attack models](#dos-attack-models)
- [Results](#results)
- [Reproducing the results](#reproducing-the-results)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Limitations](#limitations)

## The radio energy model

Energy accounting follows the standard first-order radio model from Heinzelman,
Chandrakasan and Balakrishnan, *"An Application-Specific Protocol Architecture for
Wireless Microsensor Networks,"* IEEE Trans. Wireless Communications, 2002 (the
journal version of the LEACH paper). Implemented in
[`EnergyModel`](src/main/java/io/github/vijaxx/wsn/core/EnergyModel.java):

| Constant | Value | Meaning |
|---|---|---|
| `E_elec` | 50 nJ/bit | energy to run 1 bit through the Tx or Rx electronics |
| `eps_fs` | 10 pJ/bit/m² | free-space amplifier coefficient (d < d0) |
| `eps_mp` | 0.0013 pJ/bit/m⁴ | multipath-fading amplifier coefficient (d ≥ d0) |
| `E_DA` | 5 nJ/bit/signal | data-aggregation (fusion) cost at a cluster head |
| `d0` | `sqrt(eps_fs/eps_mp)` ≈ 87.706 m | crossover distance between the two amplifier regimes |

```
E_Tx(k, d) = k·E_elec + k·eps_fs·d²     (d < d0, free space, d² path loss)
E_Tx(k, d) = k·E_elec + k·eps_mp·d⁴     (d ≥ d0, multipath, d⁴ path loss)
E_Rx(k)    = k·E_elec
E_DA(k, n) = E_DA · k · n                (fusing n incoming k-bit signals)
```

The default scenario places the base station well outside the 100 m × 100 m field
(at (50, 175)) specifically so that intra-cluster links stay in the free-space regime
while every cluster-head-to-base-station uplink falls in the more expensive multipath
regime — the same setup used in the original LEACH evaluations.

## Baseline LEACH

[`WsnSimulator`](src/main/java/io/github/vijaxx/wsn/protocol/WsnSimulator.java) in
`SecurityMode.BASELINE_LEACH` implements textbook LEACH:

1. **Probabilistic cluster-head election.** Each round, every node not yet a head this
   epoch (`epoch = round(1/p)`) draws against the threshold
   `T(n) = p / (1 - p·(r mod 1/p))`. If no node crosses threshold in a round (possible
   for small `p`), the highest-residual-energy node is forced into the role so every
   round has a functioning cluster structure.
2. **Cluster formation by nearest head.** Every non-head node joins the geographically
   nearest elected head — no authentication of any kind.
3. **TDMA schedule.** Each head hands its members sequential, non-overlapping slots
   (`TdmaSchedule`, invariant-checked in tests).
4. **Aggregation and uplink.** The head fuses all readings it received into one report
   and transmits it to the base station.

## Secure LEACH

`SecurityMode.SECURE_LEACH` runs the identical round structure but every join is
gated behind real cryptography:

- **RSA-1024 mutual authentication at join.** Every node is provisioned once, at
  deployment, with an RSA-1024 key pair and an X.509-SPKI-bound certificate signed by
  a `DeploymentAuthority` acting as the pre-deployment CA (`SHA256withRSA`).
- **AES-128 payload encryption.** Every sensor reading and every fused report is
  sealed with `AES/GCM/NoPadding` — a fresh random 96-bit IV per message, a 128-bit
  authentication tag, no IV reuse (checked by test).
- **The Interlock Protocol** for key agreement (below) — the distinctive piece.
- **Hybrid secure LEACH + TDMA.** Cluster-head election and slot assignment are
  unchanged, but a node is only added to a cluster's `TdmaSchedule` after it completes
  a successful interlock handshake with the head; a forged identity never gets a slot.
- **Reputation-based head blacklisting.** The base station knows (from the
  authenticated schedule) exactly how many members a head was responsible for; a head
  whose delivered/expected ratio stays below 50% for `blacklistThreshold` (default 3)
  consecutive rounds it chairs is excluded from future election.

## The Interlock Protocol, and why it defeats a relay MITM

Implemented in
[`InterlockParty`](src/main/java/io/github/vijaxx/wsn/security/InterlockParty.java),
adapted from Rivest and Shamir's 1984 Interlock Protocol.

Each side builds one blob: an RSA-OAEP-wrapped ephemeral AES-128 key followed by an
AES-128/GCM-sealed payload containing the sender's id, a nonce, a random secret
contribution, a hash of the sender's view of the peer's public key, and a signature
over all of it under the sender's RSA-1024 key. **The blob is cut in half**, and the
four messages run strictly in order:

```
1. A -> B : firstHalf(A), SHA-256(blob_A)
2. B -> A : firstHalf(B), SHA-256(blob_B)
3. A -> B : secondHalf(A)
4. B -> A : secondHalf(B)
```

The session key is `SHA-256(secret_lowId || secret_highId)`, truncated to 128 bits, so
neither side unilaterally picks the key.

**Why this defeats a relay attacker.** The implementation mechanically enforces the
interlock rule: `produceSecondHalf()` throws (`PROTOCOL_ORDER`) unless the peer's first
half has already arrived. An attacker on the wire is therefore always forced to send
her own first half *before* she has seen the genuine second half — and half a blob is
cryptographically useless: RSA-OAEP cannot be unwrapped from half its ciphertext, and
AES-GCM will not release plaintext without the complete ciphertext and its tag. That
denies her the one thing a relay/splice attack needs: the ability to compute an
outbound message as a function of a complete inbound one. Concretely, if she tries to:

- **forward verbatim under her own key** → the recipient's RSA unwrap or GCM tag check
  fails (`UNDECRYPTABLE`);
- **fabricate content as if from the victim** → she cannot produce a valid RSA-1024
  signature without the victim's private key (`BAD_SIGNATURE`), or if she uses her own
  certified key, the id embedded in the blob does not match the party the receiver
  registered as its peer (`IDENTITY_MISMATCH`);
- **splice a captured, previously-valid handshake back in later** → the per-sender
  `NonceCache` rejects the repeated nonce (`REPLAY`).

`InterlockPartyTest` exercises every one of these outcomes directly (10 tests), plus
the honest 4-message exchange (both sides derive the same session key) and one
uncertified-deployment case (`KEY_VIEW_MISMATCH`/`UNDECRYPTABLE`) where a substituted
public key is caught even without a CA in the loop.

**Honest scoping.** With CA-certified keys, signature verification alone already
blocks a key-substitution MITM at credential-registration time — that's shown by
`keySubstitutionMitmIsBlockedByCertificateCheck`. Interlock's *independent*
contribution is against the on-path relay/splice adversary who never has to author
content of her own, and against uncertified deployments where identity binding isn't
otherwise available. That is a narrower, more honest claim than "interlock stops all
MITM," and it's the one this implementation actually verifies.

## DoS attack models

Implemented in `io.github.vijaxx.wsn.attack`, each as a small set of hooks the
simulator calls unconditionally (`DosAttacker`):

- **Jamming** (`JammingAttacker`) — a fixed number of external RF jammers are scattered
  on the field at setup. Any transmission whose receiver is within `jammingRadius`
  of a jammer is corrupted with probability `jammingSuccessProbability`; the sender
  still pays full transmit energy (the amplifier fires regardless of what happens to
  the signal), but the packet is never delivered. This is a **physical-layer** attack
  no cryptography can stop, and the measured results below say so plainly.
- **Sybil / spoofed identity** (`SybilAttacker`) — a fixed fraction of nodes are
  compromised; each round, a compromised node's join also carries several forged
  extra identities. In baseline LEACH the head accepts every claimed identity and
  services it (spending real receive-energy on slots that will only ever carry
  noise) — an **energy-drain** DoS, not just a delivery-loss one. In secure LEACH
  every forged identity fails the certificate check and is refused a slot before any
  energy is spent on it.
- **Selective forwarding / blackhole** (`SelectiveForwardingAttacker`) — a fixed
  fraction of nodes are compromised; when a compromised node wins cluster-head
  election it silently excludes some received readings from the fused report before
  forwarding (still looks like a functioning head at the radio layer). Baseline LEACH
  has no way to notice. Secure LEACH's reputation check (above) blacklists a head that
  keeps under-delivering relative to its authenticated cluster size.

## Results

All numbers below are **measured**, not assumed — reproduce them with the command in
[the next section](#reproducing-the-results). Scenario: 60 nodes, 100 m × 100 m field,
base station at (50, 175), 0.5 J/node initial energy, 4000-bit packets, `p = 0.1`,
10% of nodes/positions adversarial where applicable, run to full network death or 2000
rounds. Three independent seeds (42, 7, 123) were run to check the findings weren't an
artifact of one RNG stream; per-seed CSVs are in [`results/`](results/).

### Headline: is the secure variant more energy-efficient?

**Total energy consumed is not a useful comparison by itself** — both protocols run
until every node's battery is empty (`allNodesDied = true` in every run below), so
total joules consumed is trivially `nodeCount × initialEnergy` for both. The
meaningful efficiency metric is **energy spent per packet actually delivered to the
base station** (lower is better), averaged across all three seeds:

| Scenario | Baseline (mJ/delivered packet) | Secure (mJ/delivered packet) | Secure vs. baseline |
|---|---|---|---|
| No attack (clean network) | 0.668 | 0.705 | **secure costs 5.5% more energy per packet** |
| Sybil attack | 0.765 | 0.705 | **secure is 7.9% more energy-efficient** |
| Selective forwarding | 0.725 | 0.730 | roughly a wash (secure +0.8% to +2.7%, one seed slightly negative) |
| Jamming | both protocols degrade badly and comparably; ratio between them is highly seed-dependent | not a reliable comparison — see below |

**This does not match the résumé's "30% energy efficiency improvement" claim, and this
simulation does not force it to.** What is actually measured is: security has a real,
consistent ~5.5% energy cost in a clean network (more bits per packet from AES-GCM's
IV+tag, plus the interlock handshake's own radio-silent compute cost), and that cost
is *more than repaid* — a swing to roughly +8% efficiency — specifically under the
sybil energy-drain attack the defense targets, because the secure variant refuses to
spend any energy servicing forged identities at all. Under selective forwarding the
energy picture is a wash, but delivery ratio (below) is consistently better. There is
no scenario in this measurement where "30%" is the honest number, in either direction.

### Full metrics (seed 42, canonical run — see `results/comparison.csv`)

| mode | attack | 1st death (round) | half dead (round) | lifetime (rounds) | packets delivered | PDR | spoofed admitted | selective drops | heads blacklisted | crypto handshake time |
|---|---|---|---|---|---|---|---|---|---|---|
| baseline | NONE | 504 | 809 | 824 | 46,938 | 1.000 | — | — | — | — |
| secure | NONE | 480 | 770 | 787 | 44,519 | 1.000 | — | — | 0 | 28.13 s |
| baseline | JAMMING | 420 | 1169 | 1691 | 11,482 | 0.162 | — | — | — | — |
| secure | JAMMING | 192 | 1506 | 1519 | 13,180 | 0.163 | — | — | 56 | 55.28 s |
| baseline | SYBIL | 510 | 699 | 714 | 40,798 | 1.000 | 18,635 | — | — | — |
| secure | SYBIL | 480 | 770 | 787 | 44,519 | 1.000 | **0** | — | 0 | 28.49 s |
| baseline | SELECTIVE_FORWARDING | 507 | 810 | 828 | 44,405 | 0.944 | — | 2,614 | — | — |
| secure | SELECTIVE_FORWARDING | 480 | 750 | 1052 | 43,229 | 0.964 | — | 1,630 | 5 | 29.05 s |

Consistent across all three seeds (42 / 7 / 123):

- **Sybil defense works completely.** Secure LEACH's `spoofedIdentitiesAdmitted` is
  **0 in every run** (18,635 / ~16,700 / ~18,900 forged identities rejected across the
  three seeds); baseline admits every single one. Secure-under-sybil lifetime and
  delivery are statistically indistinguishable from secure-under-no-attack — the
  attack is fully neutralized, not just reduced.
- **Selective-forwarding defense measurably reduces loss.** Baseline PDR under attack:
  0.944 / 0.920 / 0.901 (seeds 42/7/123) vs. secure: 0.964 / 0.955 / 0.949 — secure
  consistently loses fewer packets to the blackhole, and blacklists 5, 6, and 6 heads
  respectively across the three seeds.
- **Jamming impact is genuinely comparable between protocols, and highly variable.**
  PDR ratio (secure ÷ baseline) was 1.01× (seed 42, essentially identical), 2.41×
  (seed 7), and 2.43× (seed 123) — i.e. secure sometimes looks much better, sometimes
  not, under the *identical* attack model. This is exactly what the design predicts:
  cryptography cannot stop RF energy from colliding with a legitimate signal, so any
  apparent secure-side advantage against jamming is an **incidental side effect** of
  the selective-forwarding reputation system also reacting to low delivery ratios near
  a jammer, not a designed jamming defense. It is reported here rather than picked-and-
  chosen because it happened to look good in one run.

### Crypto overhead

Measured directly, not estimated. RSA/AES computation draws from a node's CPU power
budget, which this radio-only energy model does not represent — so overhead is
reported as wall-clock compute time and byte counts rather than joules (see
[Limitations](#limitations)):

- ~700 microseconds per interlock handshake, averaged over 40,000+ real RSA-1024 +
  AES-128-GCM handshakes in the seed-42/no-attack run (28.1 s of total handshake
  compute time across the whole simulated network lifetime).
- AES-GCM's 12-byte IV + 16-byte tag adds 224 bits of ciphertext overhead to every
  4000-bit payload (5.6%) — this is the dominant, measured cause of secure LEACH's
  extra radio energy in the clean-network comparison above, not the handshake itself
  (the handshake happens once per cluster join, not per bit transmitted).

## Reproducing the results

```
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"   # OpenJDK is keg-only on this machine
java -version   # confirm JDK 17+
mvn -version

mvn clean test                                       # 71 tests, real crypto included
mvn -q package -DskipTests
java -jar target/wsn-secure-routing-1.0.0.jar 60 42 results/comparison.csv
```

`Main` takes `[nodeCount] [seed] [outputCsv]`, all optional (defaults: 60, 42,
`results/comparison.csv`). It runs baseline and secure LEACH across all four attack
scenarios (`NONE`, `JAMMING`, `SYBIL`, `SELECTIVE_FORWARDING`), prints the comparison
table shown above, and writes every measured field to CSV. The run takes roughly
2–3 minutes at 60 nodes (secure mode runs real RSA-1024 handshakes at every cluster
join, every round) — see [`results/comparison.csv`](results/comparison.csv),
[`results/comparison_seed7.csv`](results/comparison_seed7.csv) and
[`results/comparison_seed123.csv`](results/comparison_seed123.csv) for the exact data
behind the tables above. Same seed always reproduces byte-identical results
(`WsnSimulatorTest` asserts this for both protocol modes).

## Project layout

```
src/main/java/io/github/vijaxx/wsn/
  core/       EnergyModel, Node, Cluster, TdmaSchedule, SimulationConfig
  security/   CryptoEngine, DeploymentAuthority, NodeCredential, InterlockParty,
              InterlockException, NonceCache
  attack/     DosAttacker, JammingAttacker, SybilAttacker,
              SelectiveForwardingAttacker, NoAttacker, AttackType
  protocol/   WsnSimulator (the engine), SecurityMode, SimulationResult, CryptoStats
  cli/        Main, ResultsCsvWriter
src/test/java/...                 71 JUnit 5 tests, mirrored package layout
results/                          committed CSVs backing the numbers in this README
```

## Testing

`mvn clean test` runs 71 tests with no skips and no mocks around the cryptography —
every RSA/AES/interlock test exercises the real JCA/JCE providers. Coverage includes:

- energy-model arithmetic checked against hand-computed values (free-space and
  multipath regimes, the crossover distance, continuity at `d0`)
- `Node` energy clamping/death-round bookkeeping, `TdmaSchedule` non-overlap invariant,
  `Cluster` slot assignment
- RSA sign/verify (including tamper and wrong-key rejection), RSA-OAEP key wrap/unwrap,
  AES-GCM round-trip and tamper detection, AES-CBC round-trip, HMAC, fresh-IV-per-call
- the deployment CA issuing/rejecting certificates
- the interlock handshake: honest round-trip, protocol-order enforcement, commitment-
  mismatch detection, replay rejection via `NonceCache`, identity-mismatch detection,
  key-substitution detection, and the certificate check blocking one class of MITM
  outright
- each attacker's isolated behavior (jamming radius/probability, sybil fraction
  stability, selective-forwarding drop probability)
- full-protocol integration: baseline vs. secure invariants, byte-identical
  determinism for a fixed seed (including through the crypto-random path), sybil
  defense (`spoofedIdentitiesAdmitted == 0` for secure, `> 0` for baseline),
  selective-forwarding defense, and energy-budget invariants

## Limitations

Reported plainly, not buried:

- **This is a simulation, not real hardware.** No real radios, no real MAC-layer
  collisions/backoff, no clock drift, no packet-level bit errors beyond what the
  attack models inject.
- **The MAC and propagation model are simplified.** TDMA slots are logical and
  conflict-free by construction; there is no CSMA phase, no multi-hop routing (this is
  single-hop cluster-to-base-station, as in the original LEACH), and propagation uses
  the textbook two-slope path-loss model rather than a measured trace.
- **RSA-1024 is below current recommendations** (NIST SP 800-57 sets the modern floor
  at 2048 bits). It is used here specifically because the research/résumé context this
  project reproduces specifies RSA-1024; a real deployment today should use RSA-2048+
  or an elliptic-curve alternative.
- **Base-station energy is not modeled** (assumed mains-powered, the standard WSN
  assumption); only sensor/cluster-head nodes have a battery budget.
- **Crypto overhead is reported as compute time, not joules.** RSA/AES computation
  draws from a node's CPU power budget, which this radio-only first-order energy model
  does not represent. Reporting a joule figure for it would require a CPU energy model
  this project does not implement; wall-clock time and byte overhead are reported
  instead, honestly labeled as such.
- **The jamming-vs-selective-forwarding interaction is incidental, not designed.**
  The reputation system built for the blackhole defense also reacts to jamming-induced
  low delivery ratios, which is why secure-mode jamming results vary so much by seed
  (see [Results](#results)). This project does not claim a designed jamming defense —
  cryptography cannot stop RF interference — and reports the resulting variance rather
  than picking a favorable seed.
- **Three seeds is a sanity check, not a rigorous statistical study.** The sybil and
  selective-forwarding findings are consistent across all three; a publication-grade
  claim would run dozens of seeds with confidence intervals.
