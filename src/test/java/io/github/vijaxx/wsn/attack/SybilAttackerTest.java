package io.github.vijaxx.wsn.attack;

import io.github.vijaxx.wsn.core.Node;
import io.github.vijaxx.wsn.core.SimulationConfig;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SybilAttackerTest {

    private List<Node> tenNodes() {
        List<Node> nodes = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            nodes.add(new Node(i, i, i, 1.0));
        }
        return nodes;
    }

    @Test
    void compromisedFractionMatchesConfig() {
        SimulationConfig cfg = SimulationConfig.builder().attackerFraction(0.3).nodeCount(10).build();
        SybilAttacker attacker = new SybilAttacker(cfg);
        List<Node> compromised = attacker.compromisedNodes(tenNodes(), 1, new Random(1));
        assertEquals(3, compromised.size());
    }

    @Test
    void compromisedSetIsStableAcrossRounds() {
        SimulationConfig cfg = SimulationConfig.builder().attackerFraction(0.3).nodeCount(10).build();
        SybilAttacker attacker = new SybilAttacker(cfg);
        List<Node> round1 = attacker.compromisedNodes(tenNodes(), 1, new Random(1));
        List<Node> round2 = attacker.compromisedNodes(tenNodes(), 2, new Random(99));
        assertEquals(
                round1.stream().map(Node::id).sorted().toList(),
                round2.stream().map(Node::id).sorted().toList());
    }

    @Test
    void injectsPositiveIdentityCount() {
        SimulationConfig cfg = SimulationConfig.builder().attackerFraction(0.3).nodeCount(10).build();
        SybilAttacker attacker = new SybilAttacker(cfg);
        Node n = new Node(0, 0, 0, 1.0);
        assertTrue(attacker.sybilIdentityCount(n, 1, new Random(1)) > 0);
    }
}
