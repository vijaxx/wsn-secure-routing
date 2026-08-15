package io.github.vijaxx.wsn.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NodeTest {

    @Test
    void consumeReducesEnergyByExactAmount() {
        Node n = new Node(1, 0, 0, 1.0);
        double actual = n.consume(0.3, 5);
        assertEquals(0.3, actual, 1e-12);
        assertEquals(0.7, n.energy(), 1e-12);
        assertTrue(n.alive());
    }

    @Test
    void consumeClampsAtZeroAndMarksDead() {
        Node n = new Node(1, 0, 0, 0.5);
        double actual = n.consume(10.0, 7);
        assertEquals(0.5, actual, 1e-12); // only what remained was actually drawn
        assertEquals(0.0, n.energy(), 1e-12);
        assertFalse(n.alive());
        assertEquals(7, n.deathRound());
    }

    @Test
    void consumeAfterDeathIsNoOp() {
        Node n = new Node(1, 0, 0, 0.1);
        n.consume(1.0, 3);
        assertEquals(3, n.deathRound());
        double actual = n.consume(1.0, 9);
        assertEquals(0.0, actual, 1e-12);
        assertEquals(3, n.deathRound()); // unchanged, not re-killed at round 9
    }

    @Test
    void distanceToUsesEuclideanFormula() {
        Node a = new Node(1, 0, 0, 1.0);
        Node b = new Node(2, 3, 4, 1.0);
        assertEquals(5.0, a.distanceTo(b), 1e-12);
    }

    @Test
    void resetRoundStateClearsRoleButNotEnergy() {
        Node n = new Node(1, 0, 0, 1.0);
        n.consume(0.2, 1);
        n.setClusterHead(true);
        n.setTdmaSlot(3);
        n.resetRoundState();
        assertFalse(n.isClusterHead());
        assertEquals(-1, n.tdmaSlot());
        assertEquals(0.8, n.energy(), 1e-12);
    }

    @Test
    void constructorRejectsNonPositiveInitialEnergy() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> new Node(1, 0, 0, 0.0));
    }
}
