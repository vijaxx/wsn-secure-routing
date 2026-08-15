package io.github.vijaxx.wsn.core;

import io.github.vijaxx.wsn.attack.AttackType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SimulationConfigTest {

    @Test
    void defaultsAreInternallyConsistent() {
        SimulationConfig cfg = SimulationConfig.defaults();
        assertEquals(AttackType.NONE, cfg.attack());
        assertEquals(100, cfg.nodeCount());
    }

    @Test
    void withAttackProducesIndependentCopy() {
        SimulationConfig base = SimulationConfig.defaults();
        SimulationConfig jammed = base.withAttack(AttackType.JAMMING);
        assertEquals(AttackType.NONE, base.attack());
        assertEquals(AttackType.JAMMING, jammed.attack());
        assertEquals(base.nodeCount(), jammed.nodeCount());
    }

    @Test
    void withSeedChangesOnlySeed() {
        SimulationConfig base = SimulationConfig.defaults();
        SimulationConfig reseeded = base.withSeed(999L);
        assertEquals(999L, reseeded.seed());
        assertEquals(base.nodeCount(), reseeded.nodeCount());
    }

    @Test
    void rejectsInvalidClusterHeadProbability() {
        assertThrows(IllegalArgumentException.class,
                () -> SimulationConfig.builder().clusterHeadProbability(0).build());
        assertThrows(IllegalArgumentException.class,
                () -> SimulationConfig.builder().clusterHeadProbability(1).build());
    }

    @Test
    void rejectsNonPositiveNodeCount() {
        assertThrows(IllegalArgumentException.class, () -> SimulationConfig.builder().nodeCount(0).build());
    }
}
