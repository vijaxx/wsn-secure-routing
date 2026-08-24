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

    @Test
    void acceptsProbabilityFieldsAtTheirInclusiveBounds() {
        // Unlike clusterHeadProbability, these three are genuine probabilities
        // and 0 ("never") / 1 ("always") are both legitimate configurations,
        // not just boundary noise.
        SimulationConfig.builder().attackerFraction(0.0).build();
        SimulationConfig.builder().attackerFraction(1.0).build();
        SimulationConfig.builder().jammingSuccessProbability(0.0).build();
        SimulationConfig.builder().jammingSuccessProbability(1.0).build();
        SimulationConfig.builder().selectiveDropProbability(0.0).build();
        SimulationConfig.builder().selectiveDropProbability(1.0).build();
    }

    @Test
    void rejectsOutOfRangeAttackerFraction() {
        assertThrows(IllegalArgumentException.class,
                () -> SimulationConfig.builder().attackerFraction(-0.01).build());
        assertThrows(IllegalArgumentException.class,
                () -> SimulationConfig.builder().attackerFraction(1.01).build());
    }

    @Test
    void rejectsOutOfRangeJammingSuccessProbability() {
        assertThrows(IllegalArgumentException.class,
                () -> SimulationConfig.builder().jammingSuccessProbability(-0.5).build());
        assertThrows(IllegalArgumentException.class,
                () -> SimulationConfig.builder().jammingSuccessProbability(1.5).build());
    }

    @Test
    void rejectsOutOfRangeSelectiveDropProbability() {
        // This is the case that actually bit silently before this fix: a
        // negative "probability" made rng.nextDouble() < p always false,
        // which quietly turned the attack model off instead of erroring.
        assertThrows(IllegalArgumentException.class,
                () -> SimulationConfig.builder().selectiveDropProbability(-0.75).build());
        assertThrows(IllegalArgumentException.class,
                () -> SimulationConfig.builder().selectiveDropProbability(2.0).build());
    }

    @Test
    void rejectsNonPositiveBlacklistThreshold() {
        assertThrows(IllegalArgumentException.class,
                () -> SimulationConfig.builder().blacklistThreshold(0).build());
        assertThrows(IllegalArgumentException.class,
                () -> SimulationConfig.builder().blacklistThreshold(-1).build());
    }
}
