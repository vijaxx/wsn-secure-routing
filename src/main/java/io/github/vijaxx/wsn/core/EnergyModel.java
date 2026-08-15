package io.github.vijaxx.wsn.core;

/**
 * First-order radio energy model for wireless sensor networks.
 *
 * <p>Constants and formulation follow the model introduced in:
 * W. B. Heinzelman, A. P. Chandrakasan and H. Balakrishnan,
 * "An Application-Specific Protocol Architecture for Wireless Microsensor Networks",
 * IEEE Transactions on Wireless Communications, vol. 1, no. 4, pp. 660-670, Oct. 2002.
 * (This is the journal version of the original LEACH paper; the same constants are
 * reused almost universally in the LEACH / SEP / DEEC literature.)
 *
 * <p>The radio dissipates {@code E_elec} joules per bit to run the transmitter or
 * receiver electronics, plus an amplifier term that depends on the distance to the
 * receiver. Two amplifier regimes are used:
 * <ul>
 *   <li>free-space (d^2 power loss), coefficient {@code eps_fs}, used when d &lt; d0</li>
 *   <li>multipath fading (d^4 power loss), coefficient {@code eps_mp}, used when d &gt;= d0</li>
 * </ul>
 * The crossover distance is {@code d0 = sqrt(eps_fs / eps_mp)}, which for the
 * constants below evaluates to approximately 87.7058 m. At exactly d0 the two
 * amplifier expressions are equal, so the model is continuous.
 *
 * <p>Transmit:  E_Tx(k, d) = k * E_elec + k * eps_fs * d^2        (d &lt; d0)
 * <br>          E_Tx(k, d) = k * E_elec + k * eps_mp * d^4        (d &gt;= d0)
 * <br>Receive:  E_Rx(k)    = k * E_elec
 * <br>Aggregate: E_DA * k * numberOfSignals  (cost of fusing several k-bit signals into one)
 *
 * <p>All energies are in joules, distances in metres, k in bits.
 * This class is immutable and stateless; instances are cheap to share.
 */
public final class EnergyModel {

    /** Energy dissipated per bit to run the transmitter or receiver circuitry: 50 nJ/bit. */
    public static final double E_ELEC = 50e-9;

    /** Free-space amplifier coefficient: 10 pJ/bit/m^2. */
    public static final double EPS_FS = 10e-12;

    /** Multipath amplifier coefficient: 0.0013 pJ/bit/m^4. */
    public static final double EPS_MP = 0.0013e-12;

    /** Data-aggregation (fusion) energy: 5 nJ/bit/signal. */
    public static final double E_DA = 5e-9;

    /** Crossover distance d0 = sqrt(eps_fs / eps_mp) ~= 87.70580 m. */
    public static final double D0 = Math.sqrt(EPS_FS / EPS_MP);

    private final double eElec;
    private final double epsFs;
    private final double epsMp;
    private final double eDa;
    private final double d0;

    /** Creates a model using the standard Heinzelman constants. */
    public EnergyModel() {
        this(E_ELEC, EPS_FS, EPS_MP, E_DA);
    }

    /** Creates a model with explicit constants (used by unit tests to probe the maths). */
    public EnergyModel(double eElec, double epsFs, double epsMp, double eDa) {
        if (eElec < 0 || epsFs <= 0 || epsMp <= 0 || eDa < 0) {
            throw new IllegalArgumentException("energy model constants must be positive");
        }
        this.eElec = eElec;
        this.epsFs = epsFs;
        this.epsMp = epsMp;
        this.eDa = eDa;
        this.d0 = Math.sqrt(epsFs / epsMp);
    }

    /** Crossover distance between the free-space and multipath amplifier regimes, in metres. */
    public double crossoverDistance() {
        return d0;
    }

    /**
     * Energy to transmit {@code bits} bits over {@code distance} metres.
     *
     * @param bits     payload size in bits, must be &gt;= 0
     * @param distance link distance in metres, must be &gt;= 0
     * @return joules
     */
    public double transmit(long bits, double distance) {
        requireNonNegative(bits, distance);
        double amplifier = distance < d0
                ? epsFs * distance * distance
                : epsMp * distance * distance * distance * distance;
        return bits * eElec + bits * amplifier;
    }

    /** Energy to receive {@code bits} bits. Independent of distance. */
    public double receive(long bits) {
        if (bits < 0) {
            throw new IllegalArgumentException("bits must be >= 0");
        }
        return bits * eElec;
    }

    /**
     * Energy for a cluster head to fuse {@code signals} incoming k-bit signals into
     * a single k-bit report.
     */
    public double aggregate(long bits, int signals) {
        if (bits < 0 || signals < 0) {
            throw new IllegalArgumentException("bits and signals must be >= 0");
        }
        return eDa * bits * signals;
    }

    /** Only the amplifier component of a transmission, useful for tests and diagnostics. */
    public double amplifierEnergy(long bits, double distance) {
        requireNonNegative(bits, distance);
        return transmit(bits, distance) - bits * eElec;
    }

    /** True when the link would use the multipath (d^4) amplifier regime. */
    public boolean isMultipath(double distance) {
        return distance >= d0;
    }

    private static void requireNonNegative(long bits, double distance) {
        if (bits < 0) {
            throw new IllegalArgumentException("bits must be >= 0");
        }
        if (distance < 0 || Double.isNaN(distance)) {
            throw new IllegalArgumentException("distance must be >= 0");
        }
    }
}
