package io.github.vijaxx.wsn.attack;

import io.github.vijaxx.wsn.core.Node;
import io.github.vijaxx.wsn.core.SimulationConfig;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Sybil / spoofed-identity model: a fixed fraction of legitimate nodes are compromised.
 * Each round, a compromised node's join request to its chosen cluster head also carries
 * {@code sybilIdentityCount} forged extra identities.
 *
 * <p>The <b>impact</b> is energy drain, not just delivery loss: an honest cluster head
 * in the baseline protocol admits every claimed identity to the TDMA schedule, so it
 * spends receive-energy ({@code E_elec} per bit) listening to slots that are never
 * carrying a real sensor reading, and the frame itself grows, which lengthens every
 * subsequent member's wait. This measurably shortens the head's -- and hence the
 * cluster's -- effective lifetime.
 *
 * <p>The secure protocol's defence is identity verification at join time (RSA
 * certificate check via the deployment CA, exercised through the interlock handshake):
 * a forged identity has no valid certificate and is refused a slot before any energy
 * is spent servicing it.
 */
public final class SybilAttacker extends DosAttacker {

    private final double attackerFraction;
    private final int sybilIdentityCount;
    private List<Integer> compromisedIds;

    public SybilAttacker(SimulationConfig config) {
        this.attackerFraction = config.attackerFraction();
        this.sybilIdentityCount = 5;
    }

    @Override
    public AttackType type() {
        return AttackType.SYBIL;
    }

    @Override
    public List<Node> compromisedNodes(List<Node> aliveNodes, int round, Random rng) {
        // Compromised set is chosen once (stable across rounds) the first time this is
        // called with the full population, then filtered to whoever is still alive.
        if (compromisedIds == null) {
            int count = Math.max(1, (int) Math.round(attackerFraction * aliveNodes.size()));
            List<Node> shuffled = new ArrayList<>(aliveNodes);
            shuffled.sort((a, b) -> Integer.compare(a.id(), b.id()));
            compromisedIds = new ArrayList<>();
            // Deterministic selection: every k-th node, k chosen so the fraction matches;
            // avoids consuming the shared rng stream (keeps determinism independent of
            // draw order elsewhere in the protocol).
            double step = shuffled.size() / (double) count;
            for (int i = 0; i < count; i++) {
                compromisedIds.add(shuffled.get((int) (i * step)).id());
            }
        }
        List<Node> result = new ArrayList<>();
        for (Node n : aliveNodes) {
            if (compromisedIds.contains(n.id())) {
                result.add(n);
            }
        }
        return result;
    }

    @Override
    public int sybilIdentityCount(Node attackerNode, int round, Random rng) {
        return sybilIdentityCount;
    }
}
