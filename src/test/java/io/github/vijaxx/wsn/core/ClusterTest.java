package io.github.vijaxx.wsn.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class ClusterTest {

    @Test
    void addMemberAssignsSequentialSlotsAndBacklinksHead() {
        Node head = new Node(0, 0, 0, 1.0);
        Cluster cluster = new Cluster(head);
        Node m1 = new Node(1, 1, 1, 1.0);
        Node m2 = new Node(2, 2, 2, 1.0);

        cluster.addMember(m1);
        cluster.addMember(m2);

        assertEquals(2, cluster.size());
        assertEquals(0, m1.tdmaSlot());
        assertEquals(1, m2.tdmaSlot());
        assertEquals(head.id(), m1.clusterHeadId());
        assertEquals(head.id(), m2.clusterHeadId());
        assertSame(head, cluster.head());
        assertEquals(0, cluster.schedule().slotOf(m1.id()));
    }
}
