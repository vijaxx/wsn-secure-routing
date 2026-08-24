package io.github.vijaxx.wsn.core;

import io.github.vijaxx.wsn.attack.AttackType;

/**
 * Immutable scenario description. Everything the simulator needs to produce a
 * reproducible run is in here, including the RNG seed.
 */
public final class SimulationConfig {

    private final int nodeCount;
    private final double fieldWidth;
    private final double fieldHeight;
    private final double baseStationX;
    private final double baseStationY;
    private final double initialEnergy;
    private final int packetBits;
    private final double clusterHeadProbability;
    private final int maxRounds;
    private final long seed;
    private final AttackType attack;
    private final double attackerFraction;
    private final double jammingRadius;
    private final double jammingSuccessProbability;
    private final double selectiveDropProbability;
    private final int blacklistThreshold;

    private SimulationConfig(Builder b) {
        this.nodeCount = b.nodeCount;
        this.fieldWidth = b.fieldWidth;
        this.fieldHeight = b.fieldHeight;
        this.baseStationX = b.baseStationX;
        this.baseStationY = b.baseStationY;
        this.initialEnergy = b.initialEnergy;
        this.packetBits = b.packetBits;
        this.clusterHeadProbability = b.clusterHeadProbability;
        this.maxRounds = b.maxRounds;
        this.seed = b.seed;
        this.attack = b.attack;
        this.attackerFraction = b.attackerFraction;
        this.jammingRadius = b.jammingRadius;
        this.jammingSuccessProbability = b.jammingSuccessProbability;
        this.selectiveDropProbability = b.selectiveDropProbability;
        this.blacklistThreshold = b.blacklistThreshold;
    }

    public int nodeCount() {
        return nodeCount;
    }

    public double fieldWidth() {
        return fieldWidth;
    }

    public double fieldHeight() {
        return fieldHeight;
    }

    public double baseStationX() {
        return baseStationX;
    }

    public double baseStationY() {
        return baseStationY;
    }

    public double initialEnergy() {
        return initialEnergy;
    }

    public int packetBits() {
        return packetBits;
    }

    public double clusterHeadProbability() {
        return clusterHeadProbability;
    }

    public int maxRounds() {
        return maxRounds;
    }

    public long seed() {
        return seed;
    }

    public AttackType attack() {
        return attack;
    }

    public double attackerFraction() {
        return attackerFraction;
    }

    public double jammingRadius() {
        return jammingRadius;
    }

    public double jammingSuccessProbability() {
        return jammingSuccessProbability;
    }

    public double selectiveDropProbability() {
        return selectiveDropProbability;
    }

    public int blacklistThreshold() {
        return blacklistThreshold;
    }

    public SimulationConfig withAttack(AttackType type) {
        return toBuilder().attack(type).build();
    }

    public SimulationConfig withSeed(long newSeed) {
        return toBuilder().seed(newSeed).build();
    }

    public Builder toBuilder() {
        return new Builder()
                .nodeCount(nodeCount)
                .field(fieldWidth, fieldHeight)
                .baseStation(baseStationX, baseStationY)
                .initialEnergy(initialEnergy)
                .packetBits(packetBits)
                .clusterHeadProbability(clusterHeadProbability)
                .maxRounds(maxRounds)
                .seed(seed)
                .attack(attack)
                .attackerFraction(attackerFraction)
                .jammingRadius(jammingRadius)
                .jammingSuccessProbability(jammingSuccessProbability)
                .selectiveDropProbability(selectiveDropProbability)
                .blacklistThreshold(blacklistThreshold);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Defaults follow the canonical LEACH evaluation scenario: 100 nodes uniformly
     * scattered over a 100 m x 100 m field, base station at the centre-top (50, 175)
     * so that many uplinks fall in the multipath regime, 4000-bit packets and p = 0.05.
     */
    public static SimulationConfig defaults() {
        return builder().build();
    }

    public static final class Builder {
        private int nodeCount = 100;
        private double fieldWidth = 100;
        private double fieldHeight = 100;
        private double baseStationX = 50;
        private double baseStationY = 175;
        private double initialEnergy = 2.0;
        private int packetBits = 4000;
        private double clusterHeadProbability = 0.05;
        private int maxRounds = 5000;
        private long seed = 42L;
        private AttackType attack = AttackType.NONE;
        private double attackerFraction = 0.10;
        private double jammingRadius = 30.0;
        private double jammingSuccessProbability = 0.80;
        private double selectiveDropProbability = 0.75;
        private int blacklistThreshold = 3;

        public Builder nodeCount(int v) {
            this.nodeCount = v;
            return this;
        }

        public Builder field(double w, double h) {
            this.fieldWidth = w;
            this.fieldHeight = h;
            return this;
        }

        public Builder baseStation(double x, double y) {
            this.baseStationX = x;
            this.baseStationY = y;
            return this;
        }

        public Builder initialEnergy(double v) {
            this.initialEnergy = v;
            return this;
        }

        public Builder packetBits(int v) {
            this.packetBits = v;
            return this;
        }

        public Builder clusterHeadProbability(double v) {
            this.clusterHeadProbability = v;
            return this;
        }

        public Builder maxRounds(int v) {
            this.maxRounds = v;
            return this;
        }

        public Builder seed(long v) {
            this.seed = v;
            return this;
        }

        public Builder attack(AttackType v) {
            this.attack = v;
            return this;
        }

        public Builder attackerFraction(double v) {
            this.attackerFraction = v;
            return this;
        }

        public Builder jammingRadius(double v) {
            this.jammingRadius = v;
            return this;
        }

        public Builder jammingSuccessProbability(double v) {
            this.jammingSuccessProbability = v;
            return this;
        }

        public Builder selectiveDropProbability(double v) {
            this.selectiveDropProbability = v;
            return this;
        }

        public Builder blacklistThreshold(int v) {
            this.blacklistThreshold = v;
            return this;
        }

        public SimulationConfig build() {
            if (nodeCount <= 0) {
                throw new IllegalArgumentException("nodeCount must be > 0");
            }
            if (clusterHeadProbability <= 0 || clusterHeadProbability >= 1) {
                throw new IllegalArgumentException("clusterHeadProbability must be in (0,1)");
            }
            if (packetBits <= 0) {
                throw new IllegalArgumentException("packetBits must be > 0");
            }
            if (maxRounds <= 0) {
                throw new IllegalArgumentException("maxRounds must be > 0");
            }
            if (initialEnergy <= 0) {
                throw new IllegalArgumentException("initialEnergy must be > 0");
            }
            if (attackerFraction < 0 || attackerFraction > 1) {
                throw new IllegalArgumentException("attackerFraction must be in [0,1]");
            }
            if (jammingSuccessProbability < 0 || jammingSuccessProbability > 1) {
                throw new IllegalArgumentException("jammingSuccessProbability must be in [0,1]");
            }
            if (selectiveDropProbability < 0 || selectiveDropProbability > 1) {
                throw new IllegalArgumentException("selectiveDropProbability must be in [0,1]");
            }
            if (blacklistThreshold <= 0) {
                throw new IllegalArgumentException("blacklistThreshold must be > 0");
            }
            return new SimulationConfig(this);
        }
    }
}
