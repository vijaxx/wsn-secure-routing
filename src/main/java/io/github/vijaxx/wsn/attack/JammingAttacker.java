package io.github.vijaxx.wsn.attack;

import io.github.vijaxx.wsn.core.Node;
import io.github.vijaxx.wsn.core.SimulationConfig;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * RF jamming model: a fixed number of jammer devices are scattered on the field at
 * simulation start (they are not sensor nodes and carry no energy budget or identity
 * of their own -- an external adversary). Any transmission whose receiver lies within
 * {@code jammingRadius} of a jammer is corrupted with probability
 * {@code jammingSuccessProbability}; the sender still pays the full transmit-energy
 * cost (the physics doesn't know the packet was destroyed), but the packet never counts
 * as delivered.
 *
 * <p>This is a purely physical-layer attack: no cryptographic or protocol-level defence
 * implemented here can stop RF energy from colliding with a legitimate signal. Both the
 * baseline and secure protocols are expected to suffer comparable packet loss under this
 * attack; that is reported honestly rather than papered over.
 */
public final class JammingAttacker extends DosAttacker {

    private final List<double[]> jammerPositions;
    private final double jammingRadius;
    private final double successProbability;

    public JammingAttacker(SimulationConfig config, Random setupRng) {
        this.jammingRadius = config.jammingRadius();
        this.successProbability = config.jammingSuccessProbability();
        int jammerCount = Math.max(1, (int) Math.round(config.attackerFraction() * config.nodeCount()));
        this.jammerPositions = new ArrayList<>(jammerCount);
        for (int i = 0; i < jammerCount; i++) {
            double x = setupRng.nextDouble() * config.fieldWidth();
            double y = setupRng.nextDouble() * config.fieldHeight();
            jammerPositions.add(new double[] {x, y});
        }
    }

    @Override
    public AttackType type() {
        return AttackType.JAMMING;
    }

    @Override
    public boolean isJammed(Node sender, Node receiver, int round, Random rng) {
        for (double[] jammer : jammerPositions) {
            double dx = receiver.x() - jammer[0];
            double dy = receiver.y() - jammer[1];
            double dist = Math.sqrt(dx * dx + dy * dy);
            if (dist <= jammingRadius && rng.nextDouble() < successProbability) {
                return true;
            }
        }
        return false;
    }

    public List<double[]> jammerPositions() {
        return jammerPositions;
    }
}
