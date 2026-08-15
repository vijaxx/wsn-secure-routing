package io.github.vijaxx.wsn.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A TDMA frame issued by one cluster head for one round.
 *
 * <p>Each member of the cluster is assigned exactly one slot, slots are numbered
 * {@code 0 .. size()-1} with no gaps and no duplicates. The head itself does not take
 * a member slot; it transmits its aggregate to the base station after the frame ends.
 *
 * <p>In the secure protocol the schedule is also the authorisation list for the frame:
 * a transmission arriving in slot s is only accepted if it comes from the node the
 * schedule assigns to slot s, which is what makes forged/off-slot traffic detectable.
 */
public final class TdmaSchedule {

    private final int clusterHeadId;
    private final Map<Integer, Integer> slotToNode = new LinkedHashMap<>();
    private final Map<Integer, Integer> nodeToSlot = new LinkedHashMap<>();

    public TdmaSchedule(int clusterHeadId) {
        this.clusterHeadId = clusterHeadId;
    }

    public int clusterHeadId() {
        return clusterHeadId;
    }

    /**
     * Appends the next contiguous slot for {@code nodeId}.
     *
     * @return the assigned slot index
     * @throws IllegalArgumentException if the node already holds a slot
     */
    public int assignNextSlot(int nodeId) {
        if (nodeToSlot.containsKey(nodeId)) {
            throw new IllegalArgumentException("node " + nodeId + " already has a slot");
        }
        int slot = slotToNode.size();
        slotToNode.put(slot, nodeId);
        nodeToSlot.put(nodeId, slot);
        return slot;
    }

    public int size() {
        return slotToNode.size();
    }

    public boolean isEmpty() {
        return slotToNode.isEmpty();
    }

    /** Node owning {@code slot}, or -1 if the slot is not part of this frame. */
    public int nodeAt(int slot) {
        return slotToNode.getOrDefault(slot, -1);
    }

    /** Slot owned by {@code nodeId}, or -1 if the node is not a member. */
    public int slotOf(int nodeId) {
        return nodeToSlot.getOrDefault(nodeId, -1);
    }

    public List<Integer> members() {
        return Collections.unmodifiableList(new ArrayList<>(nodeToSlot.keySet()));
    }

    /**
     * Slot-admission check used by the secure protocol: a frame transmission is valid
     * only if the claimed slot exists and belongs to the claimed sender.
     */
    public boolean isAuthorised(int nodeId, int slot) {
        return slot >= 0 && slotToNode.containsKey(slot) && slotToNode.get(slot) == nodeId;
    }

    /**
     * Structural invariant: slots are exactly {@code 0..n-1}, each held by one distinct node.
     * Exposed so tests (and assertions in the simulator) can verify no overlap ever occurs.
     */
    public boolean isWellFormed() {
        int n = slotToNode.size();
        if (nodeToSlot.size() != n) {
            return false;
        }
        for (int s = 0; s < n; s++) {
            Integer node = slotToNode.get(s);
            if (node == null) {
                return false;
            }
            Integer back = nodeToSlot.get(node);
            if (back == null || back != s) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String toString() {
        return "TdmaSchedule{head=" + clusterHeadId + ", slots=" + slotToNode + "}";
    }
}
