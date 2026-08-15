package io.github.vijaxx.wsn.attack;

/**
 * What happened to one packet attempt during one round, as seen by an attacker /
 * defence decision point. Used to accumulate per-round attack statistics.
 */
public final class RoundReport {
    public int attempted;
    public int jammed;
    public int spoofedAdmitted;
    public int spoofedRejected;
    public int droppedByBlackhole;
    public int delivered;
}
