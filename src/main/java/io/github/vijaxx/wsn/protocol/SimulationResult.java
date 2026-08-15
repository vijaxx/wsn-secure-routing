package io.github.vijaxx.wsn.protocol;

import io.github.vijaxx.wsn.attack.AttackType;

import java.util.ArrayList;
import java.util.List;

/** Aggregated outcome of one full simulation run, plus the per-round trace it was built from. */
public final class SimulationResult {

    public SecurityMode mode;
    public AttackType attack;
    public long seed;
    public int nodeCount;

    public int firstNodeDeathRound = -1;
    public int halfNodesDeathRound = -1;
    public int networkLifetimeRounds;
    public boolean allNodesDied;

    public double totalEnergyConsumedJ;
    public double totalTransmitEnergyJ;
    public double totalReceiveEnergyJ;
    public double totalAggregateEnergyJ;

    public long packetsAttempted;
    public long packetsDelivered;
    public long packetsJammed;
    public long spoofedIdentitiesAdmitted;
    public long spoofedIdentitiesRejected;
    public long selectiveDropsSuffered;
    public long headsBlacklisted;

    public final CryptoStats crypto = new CryptoStats();

    public final List<Integer> aliveCountByRound = new ArrayList<>();

    public double packetDeliveryRatio() {
        return packetsAttempted == 0 ? 0.0 : (double) packetsDelivered / packetsAttempted;
    }

    public double avgEnergyPerNode() {
        return nodeCount == 0 ? 0.0 : totalEnergyConsumedJ / nodeCount;
    }
}
