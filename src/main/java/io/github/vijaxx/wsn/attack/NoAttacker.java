package io.github.vijaxx.wsn.attack;

/** The clean-network baseline: every hook is a no-op. */
public final class NoAttacker extends DosAttacker {
    @Override
    public AttackType type() {
        return AttackType.NONE;
    }
}
