package io.github.vijaxx.wsn.attack;

import io.github.vijaxx.wsn.core.Node;

import java.util.List;
import java.util.Random;

/**
 * Base class for the three DoS attack models. Each hook defaults to "no effect"; a
 * concrete attacker overrides only the hooks its attack actually uses, so the protocol
 * runners can call every hook unconditionally without an attack-type switch scattered
 * through the simulation loop.
 */
public abstract class DosAttacker {

    public abstract AttackType type();

    /**
     * Called once per round after alive nodes are known. Lets an attacker nominate which
     * legitimate nodes are compromised this round (sybil / selective-forwarding models).
     * The returned set is a subset of {@code aliveNodes}; the protocol marks them
     * {@link Node#setCompromised(boolean)} for the round.
     */
    public List<Node> compromisedNodes(List<Node> aliveNodes, int round, Random rng) {
        return List.of();
    }

    /**
     * Number of forged/spoofed extra join requests a compromised node injects into its
     * chosen cluster head this round (sybil model). Zero for attacks that do not forge
     * identities.
     */
    public int sybilIdentityCount(Node attackerNode, int round, Random rng) {
        return 0;
    }

    /**
     * Whether the link from {@code sender} to {@code receiver} is jammed this round
     * (jamming model). Independent of identity; a purely physical-layer effect.
     */
    public boolean isJammed(Node sender, Node receiver, int round, Random rng) {
        return false;
    }

    /**
     * Whether a compromised cluster head silently drops {@code member}'s packet instead
     * of aggregating and forwarding it (selective-forwarding / blackhole model).
     */
    public boolean shouldDrop(Node head, Node member, int round, Random rng) {
        return false;
    }
}
