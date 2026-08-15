package io.github.vijaxx.wsn.attack;

import io.github.vijaxx.wsn.core.Node;
import io.github.vijaxx.wsn.core.SimulationConfig;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Selective-forwarding / blackhole model: a fixed fraction of nodes are compromised.
 * When a compromised node wins cluster-head election it aggregates every member packet
 * as normal (so the attack is silent at the radio layer) but drops each one with
 * probability {@code selectiveDropProbability} instead of relaying it to the base
 * station -- i.e. it "loses" arbitrarily many of its cluster's packets while still
 * looking like a functioning head.
 *
 * <p>The baseline protocol has no way to notice this: a head that reports low traffic
 * looks identical to a cluster that legitimately had few readings. The secure
 * protocol's defence is a simple reputation check the base station can run because the
 * TDMA schedule was authenticated at formation time (so the base station knows exactly
 * how many members a given head was supposed to relay for): if a head's measured
 * delivery ratio stays below 50% for {@code blacklistThreshold} consecutive rounds it
 * chairs, the base station blacklists it from future cluster-head election.
 */
public final class SelectiveForwardingAttacker extends DosAttacker {

    private final double attackerFraction;
    private final double dropProbability;
    private List<Integer> compromisedIds;

    public SelectiveForwardingAttacker(SimulationConfig config) {
        this.attackerFraction = config.attackerFraction();
        this.dropProbability = config.selectiveDropProbability();
    }

    @Override
    public AttackType type() {
        return AttackType.SELECTIVE_FORWARDING;
    }

    @Override
    public List<Node> compromisedNodes(List<Node> aliveNodes, int round, Random rng) {
        if (compromisedIds == null) {
            int count = Math.max(1, (int) Math.round(attackerFraction * aliveNodes.size()));
            List<Node> sorted = new ArrayList<>(aliveNodes);
            sorted.sort((a, b) -> Integer.compare(a.id(), b.id()));
            compromisedIds = new ArrayList<>();
            double step = sorted.size() / (double) count;
            for (int i = 0; i < count; i++) {
                compromisedIds.add(sorted.get((int) (i * step)).id());
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
    public boolean shouldDrop(Node head, Node member, int round, Random rng) {
        return head.compromised() && rng.nextDouble() < dropProbability;
    }
}
