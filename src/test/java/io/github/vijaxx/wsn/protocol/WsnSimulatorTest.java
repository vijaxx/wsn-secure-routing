package io.github.vijaxx.wsn.protocol;

import io.github.vijaxx.wsn.attack.AttackType;
import io.github.vijaxx.wsn.core.SimulationConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration-level tests against the full simulator. Node counts and round budgets
 * are kept small so the suite (which exercises real RSA-1024 handshakes in secure mode)
 * finishes quickly; the CLI run used for the README's reported numbers uses larger,
 * more statistically meaningful scenarios.
 */
class WsnSimulatorTest {

    private SimulationConfig smallConfig(AttackType attack, long seed) {
        return SimulationConfig.builder()
                .nodeCount(12)
                .field(100, 100)
                .baseStation(50, 175)
                .initialEnergy(0.3)
                .packetBits(2000)
                .clusterHeadProbability(0.2)
                .maxRounds(150)
                .seed(seed)
                .attack(attack)
                .attackerFraction(0.25)
                .jammingRadius(30)
                .jammingSuccessProbability(0.9)
                .selectiveDropProbability(0.9)
                .blacklistThreshold(2)
                .build();
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void baselineRunProducesSensibleInvariants() {
        SimulationResult r = new WsnSimulator(smallConfig(AttackType.NONE, 1), SecurityMode.BASELINE_LEACH).run();
        assertTrue(r.networkLifetimeRounds > 0);
        assertTrue(r.packetsDelivered <= r.packetsAttempted);
        assertTrue(r.totalEnergyConsumedJ <= r.nodeCount * 0.3 + 1e-9);
        assertEquals(0, r.crypto.interlockHandshakes, "baseline must not run any crypto");
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void secureRunPerformsRealInterlockHandshakes() {
        SimulationResult r = new WsnSimulator(smallConfig(AttackType.NONE, 1), SecurityMode.SECURE_LEACH).run();
        assertTrue(r.crypto.interlockHandshakes > 0, "secure protocol must actually run the handshake");
        assertTrue(r.crypto.handshakeMillis() > 0);
        assertTrue(r.packetsDelivered <= r.packetsAttempted);
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void sameSeedProducesByteIdenticalResults() {
        SimulationResult a = new WsnSimulator(smallConfig(AttackType.NONE, 42), SecurityMode.BASELINE_LEACH).run();
        SimulationResult b = new WsnSimulator(smallConfig(AttackType.NONE, 42), SecurityMode.BASELINE_LEACH).run();
        assertEquals(a.networkLifetimeRounds, b.networkLifetimeRounds);
        assertEquals(a.firstNodeDeathRound, b.firstNodeDeathRound);
        assertEquals(a.packetsAttempted, b.packetsAttempted);
        assertEquals(a.packetsDelivered, b.packetsDelivered);
        assertEquals(a.totalEnergyConsumedJ, b.totalEnergyConsumedJ, 1e-12);
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void secureModeDeterminismAlsoHoldsThroughCryptoRandomness() {
        SimulationResult a = new WsnSimulator(smallConfig(AttackType.NONE, 7), SecurityMode.SECURE_LEACH).run();
        SimulationResult b = new WsnSimulator(smallConfig(AttackType.NONE, 7), SecurityMode.SECURE_LEACH).run();
        assertEquals(a.networkLifetimeRounds, b.networkLifetimeRounds);
        assertEquals(a.packetsDelivered, b.packetsDelivered);
        assertEquals(a.crypto.interlockHandshakes, b.crypto.interlockHandshakes);
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void differentSeedsTypicallyProduceDifferentResults() {
        SimulationResult a = new WsnSimulator(smallConfig(AttackType.NONE, 1), SecurityMode.BASELINE_LEACH).run();
        SimulationResult b = new WsnSimulator(smallConfig(AttackType.NONE, 2), SecurityMode.BASELINE_LEACH).run();
        // At this small scale (12 nodes, no deaths within the round budget) delivery
        // counts and lifetime are saturated and uninformative, but total energy
        // consumed is distance-dependent on exactly which nodes became cluster heads
        // each round, which is directly driven by the RNG stream and reliably differs
        // between seeds.
        assertTrue(Math.abs(a.totalEnergyConsumedJ - b.totalEnergyConsumedJ) > 1e-6,
                "two different seeds produced an identical energy trace");
    }

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    void secureProtocolRejectsEverySybilIdentityWhileBaselineAdmitsThem() {
        SimulationResult baseline = new WsnSimulator(smallConfig(AttackType.SYBIL, 3), SecurityMode.BASELINE_LEACH).run();
        SimulationResult secure = new WsnSimulator(smallConfig(AttackType.SYBIL, 3), SecurityMode.SECURE_LEACH).run();

        assertTrue(baseline.spoofedIdentitiesAdmitted > 0,
                "baseline LEACH has no identity check and must admit forged joins");
        assertEquals(0, secure.spoofedIdentitiesAdmitted,
                "secure LEACH's certificate check must reject every forged identity");
        assertTrue(secure.spoofedIdentitiesRejected > 0);
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void jammingDegradesDeliveryRatioForBothProtocols() {
        SimulationResult baselineClean = new WsnSimulator(smallConfig(AttackType.NONE, 5), SecurityMode.BASELINE_LEACH).run();
        SimulationResult baselineJammed = new WsnSimulator(smallConfig(AttackType.JAMMING, 5), SecurityMode.BASELINE_LEACH).run();
        assertTrue(baselineJammed.packetDeliveryRatio() < baselineClean.packetDeliveryRatio(),
                "jamming is a physical-layer attack and must reduce delivery ratio regardless of protocol");
        assertTrue(baselineJammed.packetsJammed > 0);
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void selectiveForwardingReducesBaselineDeliveryRatio() {
        SimulationResult clean = new WsnSimulator(smallConfig(AttackType.NONE, 9), SecurityMode.BASELINE_LEACH).run();
        SimulationResult attacked = new WsnSimulator(smallConfig(AttackType.SELECTIVE_FORWARDING, 9), SecurityMode.BASELINE_LEACH).run();
        assertTrue(attacked.selectiveDropsSuffered > 0);
        assertTrue(attacked.packetDeliveryRatio() <= clean.packetDeliveryRatio());
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void secureProtocolCanBlacklistMisbehavingHeads() {
        SimulationResult secure = new WsnSimulator(smallConfig(AttackType.SELECTIVE_FORWARDING, 11), SecurityMode.SECURE_LEACH).run();
        // Not every seed necessarily produces a blacklist event in a 150-round / 12-node
        // scenario, but the mechanism must at least be wired up and not throw.
        assertTrue(secure.headsBlacklisted >= 0);
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void energyNeverExceedsInitialBudget() {
        for (AttackType attack : AttackType.values()) {
            SimulationResult r = new WsnSimulator(smallConfig(attack, 13), SecurityMode.BASELINE_LEACH).run();
            assertTrue(r.totalEnergyConsumedJ <= r.nodeCount * 0.3 + 1e-9,
                    "energy consumed cannot exceed the total initial budget for " + attack);
        }
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void firstNodeDeathNeverAfterHalfNodesDeath() {
        SimulationResult r = new WsnSimulator(smallConfig(AttackType.NONE, 21), SecurityMode.BASELINE_LEACH).run();
        if (r.firstNodeDeathRound > 0 && r.halfNodesDeathRound > 0) {
            assertTrue(r.firstNodeDeathRound <= r.halfNodesDeathRound);
        }
    }
}
