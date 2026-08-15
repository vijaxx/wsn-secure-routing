package io.github.vijaxx.wsn.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnergyModelTest {

    private final EnergyModel model = new EnergyModel();

    @Test
    void crossoverDistanceMatchesHandComputedValue() {
        // d0 = sqrt(eps_fs / eps_mp) = sqrt(10e-12 / 0.0013e-12) = sqrt(7692.307...) = 87.70580...
        double expected = Math.sqrt(10e-12 / 0.0013e-12);
        assertEquals(expected, model.crossoverDistance(), 1e-9);
        assertEquals(87.70580, model.crossoverDistance(), 1e-4);
    }

    @Test
    void transmitFreeSpaceMatchesHandComputedValue() {
        // 4000 bits over 50 m (< d0, free-space regime):
        // E = 4000*50e-9 + 4000*10e-12*50^2 = 2.0e-4 + 1.0e-4 = 3.0e-4 J
        double expected = 4000 * 50e-9 + 4000 * 10e-12 * 50 * 50;
        assertEquals(3.0e-4, expected, 1e-12);
        assertEquals(expected, model.transmit(4000, 50), 1e-12);
    }

    @Test
    void transmitMultipathMatchesHandComputedValue() {
        // 4000 bits over 150 m (>= d0, multipath regime):
        // E = 4000*50e-9 + 4000*0.0013e-12*150^4 = 2.0e-4 + 4000*0.0013e-12*5.0625e8
        double d4 = 150.0 * 150.0 * 150.0 * 150.0;
        double expected = 4000 * 50e-9 + 4000 * 0.0013e-12 * d4;
        assertEquals(expected, model.transmit(4000, 150), 1e-12);
    }

    @Test
    void transmitIsContinuousAtCrossoverDistance() {
        double d0 = model.crossoverDistance();
        double justBelow = model.transmit(4000, d0 - 1e-6);
        double justAbove = model.transmit(4000, d0 + 1e-6);
        assertEquals(justBelow, justAbove, 1e-9);
    }

    @Test
    void receiveMatchesHandComputedValue() {
        // E_Rx(4000) = 4000 * 50e-9 = 2.0e-4 J
        assertEquals(2.0e-4, model.receive(4000), 1e-12);
    }

    @Test
    void aggregateMatchesHandComputedValue() {
        // E_DA * bits * signals = 5e-9 * 4000 * 3 = 6.0e-5 J
        assertEquals(6.0e-5, model.aggregate(4000, 3), 1e-12);
    }

    @Test
    void isMultipathTracksCrossoverDistance() {
        double d0 = model.crossoverDistance();
        assertFalse(model.isMultipath(d0 - 0.001));
        assertTrue(model.isMultipath(d0));
        assertTrue(model.isMultipath(d0 + 0.001));
    }

    @Test
    void negativeDistanceRejected() {
        assertThrows(IllegalArgumentException.class, () -> model.transmit(100, -1));
    }

    @Test
    void negativeBitsRejected() {
        assertThrows(IllegalArgumentException.class, () -> model.transmit(-1, 10));
        assertThrows(IllegalArgumentException.class, () -> model.receive(-1));
    }

    @Test
    void amplifierEnergyExcludesElectronicsTerm() {
        double total = model.transmit(4000, 50);
        double elecOnly = 4000 * EnergyModel.E_ELEC;
        assertEquals(total - elecOnly, model.amplifierEnergy(4000, 50), 1e-12);
    }
}
