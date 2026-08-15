package io.github.vijaxx.wsn.attack;

import io.github.vijaxx.wsn.core.Node;
import io.github.vijaxx.wsn.core.SimulationConfig;
import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SelectiveForwardingAttackerTest {

    @Test
    void neverDropsWhenHeadIsNotCompromised() {
        SimulationConfig cfg = SimulationConfig.builder().selectiveDropProbability(1.0).build();
        SelectiveForwardingAttacker attacker = new SelectiveForwardingAttacker(cfg);
        Node head = new Node(1, 0, 0, 1.0);
        head.setCompromised(false);
        Node member = new Node(2, 1, 1, 1.0);
        for (int i = 0; i < 20; i++) {
            assertFalse(attacker.shouldDrop(head, member, i, new Random(i)));
        }
    }

    @Test
    void alwaysDropsWhenCompromisedAndProbabilityIsOne() {
        SimulationConfig cfg = SimulationConfig.builder().selectiveDropProbability(1.0).build();
        SelectiveForwardingAttacker attacker = new SelectiveForwardingAttacker(cfg);
        Node head = new Node(1, 0, 0, 1.0);
        head.setCompromised(true);
        Node member = new Node(2, 1, 1, 1.0);
        for (int i = 0; i < 20; i++) {
            assertTrue(attacker.shouldDrop(head, member, i, new Random(i)));
        }
    }
}
