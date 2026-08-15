package io.github.vijaxx.wsn.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TdmaScheduleTest {

    @Test
    void slotsAreContiguousAndNonOverlapping() {
        TdmaSchedule schedule = new TdmaSchedule(0);
        for (int i = 1; i <= 10; i++) {
            int slot = schedule.assignNextSlot(i);
            assertEquals(i - 1, slot);
        }
        assertTrue(schedule.isWellFormed());
        assertEquals(10, schedule.size());
        // no two members share a slot, and every slot 0..9 is occupied by exactly one node
        java.util.Set<Integer> seenSlots = new java.util.HashSet<>();
        for (int member = 1; member <= 10; member++) {
            int slot = schedule.slotOf(member);
            assertTrue(seenSlots.add(slot), "slot " + slot + " assigned to more than one member");
        }
    }

    @Test
    void duplicateAssignmentRejected() {
        TdmaSchedule schedule = new TdmaSchedule(0);
        schedule.assignNextSlot(5);
        assertThrows(IllegalArgumentException.class, () -> schedule.assignNextSlot(5));
    }

    @Test
    void isAuthorisedOnlyForTheOwningNodeAtItsSlot() {
        TdmaSchedule schedule = new TdmaSchedule(0);
        int slot = schedule.assignNextSlot(42);
        assertTrue(schedule.isAuthorised(42, slot));
        assertFalse(schedule.isAuthorised(43, slot));
        assertFalse(schedule.isAuthorised(42, slot + 1));
    }

    @Test
    void emptyScheduleIsWellFormed() {
        TdmaSchedule schedule = new TdmaSchedule(0);
        assertTrue(schedule.isEmpty());
        assertTrue(schedule.isWellFormed());
    }
}
