package io.github.vijaxx.wsn.cli;

import io.github.vijaxx.wsn.attack.AttackType;
import io.github.vijaxx.wsn.core.SimulationConfig;
import io.github.vijaxx.wsn.protocol.SecurityMode;
import io.github.vijaxx.wsn.protocol.SimulationResult;
import io.github.vijaxx.wsn.protocol.WsnSimulator;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Runs baseline LEACH and secure LEACH across the clean network and all three DoS
 * attack models, prints a comparison table, and writes the full results to CSV.
 *
 * <p>Usage: {@code java -jar wsn-secure-routing.jar [nodeCount] [seed] [outputCsv]}
 * All arguments are optional; defaults match {@link SimulationConfig#defaults()}.
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) throws IOException {
        int nodeCount = args.length > 0 ? Integer.parseInt(args[0]) : 60;
        long seed = args.length > 1 ? Long.parseLong(args[1]) : 42L;
        Path out = Path.of(args.length > 2 ? args[2] : "results/comparison.csv");

        SimulationConfig base = SimulationConfig.builder()
                .nodeCount(nodeCount)
                .field(100, 100)
                .baseStation(50, 175)
                .initialEnergy(0.5)
                .packetBits(4000)
                .clusterHeadProbability(0.1)
                .maxRounds(2000)
                .seed(seed)
                .attackerFraction(0.10)
                .jammingRadius(30.0)
                .jammingSuccessProbability(0.80)
                .selectiveDropProbability(0.75)
                .blacklistThreshold(3)
                .build();

        List<SimulationResult> results = new ArrayList<>();
        for (AttackType attack : AttackType.values()) {
            SimulationConfig cfg = base.withAttack(attack);
            long t0 = System.nanoTime();
            SimulationResult baseline = new WsnSimulator(cfg, SecurityMode.BASELINE_LEACH).run();
            long t1 = System.nanoTime();
            SimulationResult secure = new WsnSimulator(cfg, SecurityMode.SECURE_LEACH).run();
            long t2 = System.nanoTime();
            System.out.printf(Locale.ROOT, "[%s] baseline %.1fs, secure %.1fs%n",
                    attack, (t1 - t0) / 1e9, (t2 - t1) / 1e9);
            results.add(baseline);
            results.add(secure);
        }

        printTable(results);

        if (out.getParent() != null) {
            java.nio.file.Files.createDirectories(out.getParent());
        }
        ResultsCsvWriter.write(out, results);
        System.out.println();
        System.out.println("Full results written to " + out.toAbsolutePath());
    }

    private static void printTable(List<SimulationResult> results) {
        String fmt = "%-10s %-22s %8s %8s %10s %14s %10s %8s %10s%n";
        System.out.println();
        System.out.printf(Locale.ROOT, fmt, "mode", "attack", "1stDeath", "halfDead",
                "lifetime", "energyJ", "PDR", "delivered", "handshkMs");
        for (SimulationResult r : results) {
            System.out.printf(Locale.ROOT, fmt,
                    r.mode == SecurityMode.BASELINE_LEACH ? "baseline" : "secure",
                    r.attack,
                    r.firstNodeDeathRound,
                    r.halfNodesDeathRound,
                    r.networkLifetimeRounds,
                    String.format(Locale.ROOT, "%.4f", r.totalEnergyConsumedJ),
                    String.format(Locale.ROOT, "%.4f", r.packetDeliveryRatio()),
                    r.packetsDelivered,
                    String.format(Locale.ROOT, "%.1f", r.crypto.handshakeMillis()));
        }
    }
}
