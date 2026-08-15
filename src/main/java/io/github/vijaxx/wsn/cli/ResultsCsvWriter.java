package io.github.vijaxx.wsn.cli;

import io.github.vijaxx.wsn.protocol.SimulationResult;

import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/** Writes one row per {@link SimulationResult} to a CSV file. */
public final class ResultsCsvWriter {

    private static final String HEADER = String.join(",",
            "mode", "attack", "seed", "nodeCount",
            "firstNodeDeathRound", "halfNodesDeathRound", "networkLifetimeRounds", "allNodesDied",
            "totalEnergyConsumedJ", "avgEnergyPerNodeJ",
            "packetsAttempted", "packetsDelivered", "packetsJammed", "packetDeliveryRatio",
            "spoofedIdentitiesAdmitted", "spoofedIdentitiesRejected",
            "selectiveDropsSuffered", "headsBlacklisted",
            "interlockHandshakes", "authenticationFailures", "handshakeMillis", "avgHandshakeMicros",
            "extraOverheadBits");

    private ResultsCsvWriter() {
    }

    public static void write(Path path, List<SimulationResult> results) throws IOException {
        try (Writer w = Files.newBufferedWriter(path)) {
            w.write(HEADER);
            w.write('\n');
            for (SimulationResult r : results) {
                w.write(row(r));
                w.write('\n');
            }
        }
    }

    private static String row(SimulationResult r) {
        return String.join(",",
                r.mode.name(), r.attack.name(), Long.toString(r.seed), Integer.toString(r.nodeCount),
                Integer.toString(r.firstNodeDeathRound), Integer.toString(r.halfNodesDeathRound),
                Integer.toString(r.networkLifetimeRounds), Boolean.toString(r.allNodesDied),
                fmt(r.totalEnergyConsumedJ), fmt(r.avgEnergyPerNode()),
                Long.toString(r.packetsAttempted), Long.toString(r.packetsDelivered),
                Long.toString(r.packetsJammed), fmt(r.packetDeliveryRatio()),
                Long.toString(r.spoofedIdentitiesAdmitted), Long.toString(r.spoofedIdentitiesRejected),
                Long.toString(r.selectiveDropsSuffered), Long.toString(r.headsBlacklisted),
                Long.toString(r.crypto.interlockHandshakes), Long.toString(r.crypto.authenticationFailures),
                fmt(r.crypto.handshakeMillis()), fmt(r.crypto.avgHandshakeMicros()),
                Long.toString(r.crypto.extraOverheadBits));
    }

    private static String fmt(double v) {
        return String.format(Locale.ROOT, "%.6f", v);
    }
}
