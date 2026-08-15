package io.github.vijaxx.wsn.attack;

import io.github.vijaxx.wsn.core.Node;
import io.github.vijaxx.wsn.core.SimulationConfig;
import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class JammingAttackerTest {

    @Test
    void outsideJammingRadiusIsNeverJammed() {
        SimulationConfig cfg = SimulationConfig.builder()
                .jammingRadius(5).jammingSuccessProbability(1.0).attackerFraction(0.5).nodeCount(4).build();
        JammingAttacker attacker = new JammingAttacker(cfg, new Random(1));
        Node sender = new Node(1, 0, 0, 1.0);
        Node farReceiver = new Node(2, 10_000, 10_000, 1.0);
        assertFalse(attacker.isJammed(sender, farReceiver, 1, new Random(2)));
    }

    @Test
    void withinRadiusAndCertainSuccessAlwaysJams() {
        SimulationConfig cfg = SimulationConfig.builder()
                .jammingRadius(1000).jammingSuccessProbability(1.0).attackerFraction(1.0).nodeCount(4)
                .field(10, 10).build();
        JammingAttacker attacker = new JammingAttacker(cfg, new Random(1));
        Node sender = new Node(1, 0, 0, 1.0);
        Node receiver = new Node(2, 5, 5, 1.0);
        for (int i = 0; i < 20; i++) {
            assertEquals(true, attacker.isJammed(sender, receiver, i, new Random(i)));
        }
    }

    @Test
    void jammerCountScalesWithAttackerFraction() {
        SimulationConfig cfg = SimulationConfig.builder().nodeCount(20).attackerFraction(0.2).build();
        JammingAttacker attacker = new JammingAttacker(cfg, new Random(1));
        assertEquals(4, attacker.jammerPositions().size());
    }
}
