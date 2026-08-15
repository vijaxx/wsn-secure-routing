package io.github.vijaxx.wsn.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** One cluster for one round: a head, its members, and the TDMA frame the head issued. */
public final class Cluster {

    private final Node head;
    private final List<Node> members = new ArrayList<>();
    private final TdmaSchedule schedule;

    public Cluster(Node head) {
        this.head = head;
        this.schedule = new TdmaSchedule(head.id());
    }

    public Node head() {
        return head;
    }

    public List<Node> members() {
        return Collections.unmodifiableList(members);
    }

    public TdmaSchedule schedule() {
        return schedule;
    }

    public int size() {
        return members.size();
    }

    /** Adds a member and immediately gives it the next TDMA slot. */
    public void addMember(Node node) {
        members.add(node);
        int slot = schedule.assignNextSlot(node.id());
        node.setTdmaSlot(slot);
        node.setClusterHeadId(head.id());
    }
}
