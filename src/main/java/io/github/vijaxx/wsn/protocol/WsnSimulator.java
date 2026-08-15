package io.github.vijaxx.wsn.protocol;

import io.github.vijaxx.wsn.attack.AttackType;
import io.github.vijaxx.wsn.attack.DosAttacker;
import io.github.vijaxx.wsn.attack.JammingAttacker;
import io.github.vijaxx.wsn.attack.NoAttacker;
import io.github.vijaxx.wsn.attack.SelectiveForwardingAttacker;
import io.github.vijaxx.wsn.attack.SybilAttacker;
import io.github.vijaxx.wsn.core.Cluster;
import io.github.vijaxx.wsn.core.EnergyModel;
import io.github.vijaxx.wsn.core.Node;
import io.github.vijaxx.wsn.core.SimulationConfig;
import io.github.vijaxx.wsn.security.CryptoEngine;
import io.github.vijaxx.wsn.security.DeploymentAuthority;
import io.github.vijaxx.wsn.security.InterlockException;
import io.github.vijaxx.wsn.security.InterlockParty;
import io.github.vijaxx.wsn.security.NodeCredential;
import io.github.vijaxx.wsn.security.NonceCache;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * The discrete-event engine. One instance runs one scenario (a {@link SecurityMode}
 * under a given {@link AttackType}) to completion and returns a {@link SimulationResult}.
 *
 * <p>Round structure, both modes:
 * <ol>
 *   <li>drop dead nodes; if none remain, stop</li>
 *   <li>attacker marks this round's compromised nodes</li>
 *   <li>LEACH probabilistic cluster-head election</li>
 *   <li>cluster formation: every non-head node joins its nearest alive head
 *       (secure mode: only after a successful certified interlock handshake)</li>
 *   <li>TDMA data phase: members transmit to their head (subject to jamming), the head
 *       aggregates admitted readings and (subject to jamming and, for a compromised
 *       head, selective forwarding) forwards the fused report to the base station</li>
 * </ol>
 *
 * <p>Same seed, same config, same mode and attack always produce byte-identical
 * results: the only source of randomness is a single {@link Random} seeded from
 * {@link SimulationConfig#seed()} (crypto randomness is likewise drawn from a seeded
 * {@link CryptoEngine} in secure mode), and iteration order is always by ascending
 * node id.
 */
public final class WsnSimulator {

    private final SimulationConfig config;
    private final SecurityMode mode;
    private final EnergyModel energyModel = new EnergyModel();

    public WsnSimulator(SimulationConfig config, SecurityMode mode) {
        this.config = config;
        this.mode = mode;
    }

    public SimulationResult run() {
        Random rng = new Random(config.seed());
        Random placementRng = new Random(config.seed() ^ 0x9E3779B97F4A7C15L);
        Random attackerSetupRng = new Random(config.seed() ^ 0x5EED5EEDL);

        List<Node> nodes = new ArrayList<>(config.nodeCount());
        for (int i = 0; i < config.nodeCount(); i++) {
            double x = placementRng.nextDouble() * config.fieldWidth();
            double y = placementRng.nextDouble() * config.fieldHeight();
            nodes.add(new Node(i, x, y, config.initialEnergy()));
        }

        DosAttacker attacker = buildAttacker(attackerSetupRng);

        // ---- secure-mode-only setup: PKI provisioning and crypto plumbing ----
        boolean secure = mode == SecurityMode.SECURE_LEACH;
        CryptoEngine engine = secure ? new CryptoEngine(config.seed()) : null;
        DeploymentAuthority ca = secure ? new DeploymentAuthority(engine) : null;
        Map<Integer, NodeCredential> credentials = new HashMap<>();
        if (secure) {
            for (Node n : nodes) {
                credentials.put(n.id(), ca.provision(n.id()));
            }
        }
        NonceCache nonceCache = secure ? new NonceCache(64) : null;
        Map<Integer, Integer> consecutiveBadRounds = new HashMap<>();

        // Forged-identity fixture for the sybil model: a sybil node never has a real
        // certificate, so a single reusable (uncertified) key pair is enough to exercise
        // "join attempt with no valid credential" without paying RSA keygen (~40ms) on
        // every one of the potentially thousands of forged join attempts in a run.
        NodeCredential forgerStub = secure
                ? new NodeCredential(-1, engine.generateRsaKeyPair(), new byte[128], ca.caPublicKey())
                : null;
        byte[] forgerEncodedKey = secure ? CryptoEngine.encodePublicKey(forgerStub.publicKey()) : null;

        SimulationResult result = new SimulationResult();
        result.mode = mode;
        result.attack = config.attack();
        result.seed = config.seed();
        result.nodeCount = config.nodeCount();

        int epoch = Math.max(1, (int) Math.round(1.0 / config.clusterHeadProbability()));
        int round = 0;

        while (round < config.maxRounds()) {
            round++;
            List<Node> alive = new ArrayList<>();
            for (Node n : nodes) {
                if (n.alive()) {
                    alive.add(n);
                    n.resetRoundState();
                    n.setCompromised(false);
                }
            }
            if (alive.isEmpty()) {
                result.allNodesDied = true;
                result.networkLifetimeRounds = round - 1;
                break;
            }

            for (Node c : attacker.compromisedNodes(alive, round, rng)) {
                c.setCompromised(true);
            }

            List<Node> heads = electClusterHeads(alive, round, epoch, rng);
            List<Cluster> clusters = formClusters(heads);

            for (Node member : alive) {
                if (member.isClusterHead()) {
                    continue;
                }
                Cluster target = nearestCluster(member, clusters);
                if (target == null) {
                    continue;
                }
                boolean admitted = true;
                if (secure) {
                    admitted = attemptSecureJoin(member, target.head(), credentials, engine,
                            nonceCache, result.crypto);
                }
                if (admitted) {
                    target.addMember(member);
                }

                if (attacker.type() == AttackType.SYBIL && member.compromised()) {
                    int forged = attacker.sybilIdentityCount(member, round, rng);
                    for (int k = 0; k < forged; k++) {
                        boolean forgedAdmitted;
                        if (secure) {
                            forgedAdmitted = attemptForgedJoin(engine, ca, nonceCache, result.crypto,
                                    forgerStub, forgerEncodedKey);
                        } else {
                            forgedAdmitted = true;
                        }
                        if (forgedAdmitted) {
                            result.spoofedIdentitiesAdmitted++;
                            // Baseline head pays real receive-energy servicing a slot that
                            // will only ever carry noise -- this is the sybil energy-drain.
                            target.head().consume(energyModel.receive(config.packetBits()), round);
                        } else {
                            result.spoofedIdentitiesRejected++;
                        }
                    }
                }
            }

            runDataPhase(clusters, attacker, rng, round, secure, result, consecutiveBadRounds);

            int aliveAfter = 0;
            for (Node n : nodes) {
                if (n.alive()) {
                    aliveAfter++;
                }
            }
            result.aliveCountByRound.add(aliveAfter);
            if (result.firstNodeDeathRound < 0 && aliveAfter < alive.size()) {
                result.firstNodeDeathRound = round;
            }
            if (result.halfNodesDeathRound < 0 && aliveAfter <= config.nodeCount() / 2) {
                result.halfNodesDeathRound = round;
            }
            if (aliveAfter == 0) {
                result.allNodesDied = true;
                result.networkLifetimeRounds = round;
                break;
            }
            result.networkLifetimeRounds = round;
        }

        for (Node n : nodes) {
            result.totalEnergyConsumedJ += n.consumedEnergy();
        }
        for (Integer blk : consecutiveBadRounds.values()) {
            // no-op; blacklist count tracked separately below
        }
        for (Node n : nodes) {
            if (n.blacklisted()) {
                result.headsBlacklisted++;
            }
        }
        return result;
    }

    // ---------------------------------------------------------------- setup helpers

    private DosAttacker buildAttacker(Random attackerSetupRng) {
        return switch (config.attack()) {
            case NONE -> new NoAttacker();
            case JAMMING -> new JammingAttacker(config, attackerSetupRng);
            case SYBIL -> new SybilAttacker(config);
            case SELECTIVE_FORWARDING -> new SelectiveForwardingAttacker(config);
        };
    }

    // ---------------------------------------------------------------- election / clustering

    private List<Node> electClusterHeads(List<Node> alive, int round, int epoch, Random rng) {
        List<Node> heads = new ArrayList<>();
        double p = config.clusterHeadProbability();
        for (Node n : alive) {
            if (mode == SecurityMode.SECURE_LEACH && n.blacklisted()) {
                continue;
            }
            boolean eligible = n.lastClusterHeadRound() < 0
                    || (round - n.lastClusterHeadRound()) >= epoch;
            if (!eligible) {
                continue;
            }
            double threshold = p / (1.0 - p * ((round - 1) % epoch));
            if (rng.nextDouble() < threshold) {
                n.setClusterHead(true);
                n.setLastClusterHeadRound(round);
                heads.add(n);
            }
        }
        if (heads.isEmpty()) {
            Node best = null;
            for (Node n : alive) {
                if (mode == SecurityMode.SECURE_LEACH && n.blacklisted()) {
                    continue;
                }
                if (best == null || n.energy() > best.energy()) {
                    best = n;
                }
            }
            if (best == null) {
                // every alive node is blacklisted; fall back to allowing the highest-energy one
                for (Node n : alive) {
                    if (best == null || n.energy() > best.energy()) {
                        best = n;
                    }
                }
            }
            if (best != null) {
                best.setClusterHead(true);
                best.setLastClusterHeadRound(round);
                heads.add(best);
            }
        }
        return heads;
    }

    private List<Cluster> formClusters(List<Node> heads) {
        List<Cluster> clusters = new ArrayList<>(heads.size());
        for (Node h : heads) {
            clusters.add(new Cluster(h));
        }
        return clusters;
    }

    private Cluster nearestCluster(Node member, List<Cluster> clusters) {
        Cluster best = null;
        double bestDist = Double.MAX_VALUE;
        for (Cluster c : clusters) {
            double d = member.distanceTo(c.head());
            if (d < bestDist) {
                bestDist = d;
                best = c;
            }
        }
        return best;
    }

    // ---------------------------------------------------------------- secure join

    /**
     * Full certified interlock handshake between {@code member} and {@code head}.
     * Returns true iff both directions authenticate; the resulting AES-128 session
     * key is discarded after use here (a real deployment would cache it for the data
     * phase's AES-GCM encryption, which is exercised directly in {@link #runDataPhase}).
     */
    private boolean attemptSecureJoin(Node member, Node head, Map<Integer, NodeCredential> credentials,
                                       CryptoEngine engine, NonceCache nonceCache, CryptoStats stats) {
        long t0 = System.nanoTime();
        try {
            NodeCredential memberCred = credentials.get(member.id());
            NodeCredential headCred = credentials.get(head.id());
            InterlockParty a = new InterlockParty(engine, memberCred, true, nonceCache);
            InterlockParty b = new InterlockParty(engine, headCred, true, nonceCache);

            a.receivePeerCredential(headCred.nodeId(), CryptoEngine.encodePublicKey(headCred.publicKey()), headCred.certificate());
            b.receivePeerCredential(memberCred.nodeId(), CryptoEngine.encodePublicKey(memberCred.publicKey()), memberCred.certificate());

            byte[] aFirst = a.produceFirstHalf();
            byte[] aCommit = a.commitment();
            byte[] bFirst = b.produceFirstHalf();
            byte[] bCommit = b.commitment();

            b.receiveFirstHalf(aFirst, aCommit);
            a.receiveFirstHalf(bFirst, bCommit);

            byte[] aSecond = a.produceSecondHalf();
            byte[] bSecond = b.produceSecondHalf();

            b.receiveSecondHalf(aSecond);
            a.receiveSecondHalf(bSecond);

            member.setAuthenticated(true);
            head.setAuthenticated(true);
            stats.interlockHandshakes++;
            stats.rsaSignVerifyOps += 4;
            stats.rsaWrapUnwrapOps += 4;
            stats.aesEncryptOps += 2;
            stats.aesDecryptOps += 2;
            return true;
        } catch (InterlockException e) {
            stats.authenticationFailures++;
            return false;
        } finally {
            stats.handshakeNanos += System.nanoTime() - t0;
        }
    }

    /**
     * A sybil identity has no provisioned credential, so it cannot pass certificate
     * checks. The reusable {@code forgerStub}/{@code forgerEncodedKey} avoid paying RSA
     * keygen on every forged attempt; the outcome does not depend on which garbage bytes
     * are offered, only on the fact that no valid CA certificate exists for them.
     */
    private boolean attemptForgedJoin(CryptoEngine engine, DeploymentAuthority ca,
                                       NonceCache nonceCache, CryptoStats stats,
                                       NodeCredential forgerStub, byte[] forgerEncodedKey) {
        long t0 = System.nanoTime();
        try {
            InterlockParty honestSide = new InterlockParty(engine, forgerStub, true, nonceCache);
            // receivePeerCredential always throws here: the certificate is garbage and
            // cannot verify under the deployment CA.
            honestSide.receivePeerCredential(999_000, forgerEncodedKey, forgerStub.certificate());
            return true; // unreachable
        } catch (InterlockException e) {
            stats.authenticationFailures++;
            return false;
        } finally {
            stats.handshakeNanos += System.nanoTime() - t0;
        }
    }

    // ---------------------------------------------------------------- data phase

    private void runDataPhase(List<Cluster> clusters, DosAttacker attacker, Random rng, int round,
                               boolean secure, SimulationResult result,
                               Map<Integer, Integer> consecutiveBadRounds) {
        int baseBits = config.packetBits();
        // AES-GCM adds a 12-byte IV and a 16-byte tag to every encrypted payload.
        int cryptoOverheadBits = secure ? (CryptoEngine.GCM_IV_BYTES + 16) * 8 : 0;
        int bits = baseBits + cryptoOverheadBits;

        for (Cluster cluster : clusters) {
            Node head = cluster.head();
            if (!head.alive()) {
                continue;
            }
            int received = 0;
            int included = 0;

            for (Node member : cluster.members()) {
                if (!member.alive()) {
                    continue;
                }
                result.packetsAttempted++;
                double dist = member.distanceTo(head);
                member.consume(energyModel.transmit(bits, dist), round);
                if (secure) {
                    result.crypto.aesEncryptOps++;
                    result.crypto.extraOverheadBits += cryptoOverheadBits;
                }

                if (attacker.isJammed(member, head, round, rng)) {
                    result.packetsJammed++;
                    continue;
                }
                head.consume(energyModel.receive(bits), round);
                if (secure) {
                    result.crypto.aesDecryptOps++;
                }
                received++;

                if (head.compromised() && attacker.shouldDrop(head, member, round, rng)) {
                    result.selectiveDropsSuffered++;
                    continue;
                }
                included++;
            }
            // the head's own reading is always part of the fused report
            included++;
            result.packetsAttempted++;

            if (received > 0) {
                head.consume(energyModel.aggregate(bits, received), round);
            }

            double distToBs = head.distanceTo(config.baseStationX(), config.baseStationY());
            head.consume(energyModel.transmit(bits, distToBs), round);
            if (secure) {
                result.crypto.aesEncryptOps++;
            }

            boolean uplinkJammed = attacker.isJammed(head, headAsBsProxy(head), round, rng);
            if (!uplinkJammed) {
                result.packetsDelivered += included;
            } else {
                result.packetsJammed += included;
            }

            if (secure) {
                updateReputation(head, cluster.size() + 1, included, consecutiveBadRounds, result);
            }
        }
    }

    /** Jamming is checked against a receiver position; the base station is a fixed point,
     *  so this adapts {@link DosAttacker#isJammed} (which takes a Node) to that point by
     *  wrapping it in a throwaway Node at the base station's coordinates. */
    private Node headAsBsProxy(Node head) {
        Node bs = new Node(-1, config.baseStationX(), config.baseStationY(), 1.0);
        return bs;
    }

    /**
     * Reputation-based blacklisting: if a head's delivered/expected ratio for its own
     * chairing stays at or below 50% for {@code blacklistThreshold} consecutive rounds,
     * it is excluded from future election. Only meaningful in secure mode, where the
     * base station can trust the authenticated cluster size it is comparing against.
     */
    private void updateReputation(Node head, int expected, int included,
                                   Map<Integer, Integer> consecutiveBadRounds,
                                   SimulationResult result) {
        boolean bad = expected > 0 && (included / (double) expected) < 0.5;
        int streak = consecutiveBadRounds.getOrDefault(head.id(), 0);
        streak = bad ? streak + 1 : 0;
        consecutiveBadRounds.put(head.id(), streak);
        if (streak >= config.blacklistThreshold()) {
            head.setBlacklisted(true);
        }
    }
}
