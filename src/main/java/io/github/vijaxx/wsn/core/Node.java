package io.github.vijaxx.wsn.core;

/**
 * A single sensor node: a fixed position on the field plus a finite energy budget.
 *
 * <p>Nodes are mutable simulation state. A node is "alive" while its residual energy
 * is strictly positive; once a charge would take it to or below zero it is marked dead
 * and stops participating.
 */
public final class Node {

    private final int id;
    private final double x;
    private final double y;
    private final double initialEnergy;

    private double energy;
    private boolean alive = true;
    private int deathRound = -1;

    /** Round index at which this node was last a cluster head, or a large negative sentinel. */
    private int lastClusterHeadRound = Integer.MIN_VALUE / 2;

    /** Set each round by the protocol. */
    private boolean clusterHead;
    private int clusterHeadId = -1;
    private int tdmaSlot = -1;

    /** Set when the base station's reputation module blacklists this node from head election. */
    private boolean blacklisted;

    /** True when the node has completed the (secure) join handshake. */
    private boolean authenticated;

    /** True for nodes the adversary has compromised (selective-forwarding model). */
    private boolean compromised;

    public Node(int id, double x, double y, double initialEnergy) {
        if (initialEnergy <= 0) {
            throw new IllegalArgumentException("initial energy must be > 0");
        }
        this.id = id;
        this.x = x;
        this.y = y;
        this.initialEnergy = initialEnergy;
        this.energy = initialEnergy;
    }

    public int id() {
        return id;
    }

    public double x() {
        return x;
    }

    public double y() {
        return y;
    }

    public double energy() {
        return energy;
    }

    public double initialEnergy() {
        return initialEnergy;
    }

    public double consumedEnergy() {
        return initialEnergy - energy;
    }

    public boolean alive() {
        return alive;
    }

    public int deathRound() {
        return deathRound;
    }

    public boolean isClusterHead() {
        return clusterHead;
    }

    public void setClusterHead(boolean clusterHead) {
        this.clusterHead = clusterHead;
    }

    public int clusterHeadId() {
        return clusterHeadId;
    }

    public void setClusterHeadId(int clusterHeadId) {
        this.clusterHeadId = clusterHeadId;
    }

    public int tdmaSlot() {
        return tdmaSlot;
    }

    public void setTdmaSlot(int tdmaSlot) {
        this.tdmaSlot = tdmaSlot;
    }

    public int lastClusterHeadRound() {
        return lastClusterHeadRound;
    }

    public void setLastClusterHeadRound(int round) {
        this.lastClusterHeadRound = round;
    }

    public boolean blacklisted() {
        return blacklisted;
    }

    public void setBlacklisted(boolean blacklisted) {
        this.blacklisted = blacklisted;
    }

    public boolean authenticated() {
        return authenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }

    public boolean compromised() {
        return compromised;
    }

    public void setCompromised(boolean compromised) {
        this.compromised = compromised;
    }

    /** Euclidean distance to another node, in metres. */
    public double distanceTo(Node other) {
        return distanceTo(other.x, other.y);
    }

    /** Euclidean distance to an arbitrary point, in metres. */
    public double distanceTo(double px, double py) {
        double dx = x - px;
        double dy = y - py;
        return Math.sqrt(dx * dx + dy * dy);
    }

    /**
     * Draws {@code joules} from the node's budget.
     *
     * @param joules energy to consume, must be &gt;= 0
     * @param round  current round index, recorded if this charge kills the node
     * @return the energy actually consumed; it is clamped so residual energy never goes negative
     */
    public double consume(double joules, int round) {
        if (joules < 0 || Double.isNaN(joules)) {
            throw new IllegalArgumentException("energy to consume must be >= 0");
        }
        if (!alive) {
            return 0.0;
        }
        double actual = Math.min(joules, energy);
        energy -= actual;
        if (energy <= 0) {
            energy = 0;
            alive = false;
            deathRound = round;
        }
        return actual;
    }

    /** Resets the per-round role fields. Does not touch energy or liveness. */
    public void resetRoundState() {
        clusterHead = false;
        clusterHeadId = -1;
        tdmaSlot = -1;
    }

    @Override
    public String toString() {
        return "Node{" + id + " @(" + String.format("%.1f", x) + "," + String.format("%.1f", y)
                + ") E=" + String.format("%.6f", energy) + (alive ? "" : " DEAD") + "}";
    }
}
