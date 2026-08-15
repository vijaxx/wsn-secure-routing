package io.github.vijaxx.wsn.attack;

/** The DoS attack models a scenario can run under, or {@link #NONE} for a clean baseline. */
public enum AttackType {
    NONE,
    JAMMING,
    SYBIL,
    SELECTIVE_FORWARDING
}
