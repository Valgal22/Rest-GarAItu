package pbl.restserver.model;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class MemberTest {

  @Test
  void gettersSetters_work() {
    FamilyGroup g = new FamilyGroup("G");
    g.setId(1L);

    Member m = new Member();
    m.setId(7L);
    m.setFamilyGroup(g);
    m.setName("Ana");
    m.setEmail("ana@x.com");
    m.setContext("ctx");
    m.setRole((short) 2);
    m.setPasswordHash("hash");
    m.setEmbedding(new byte[] {1,2,3});

    assertEquals(7L, m.getId());
    assertEquals(1L, m.getFamilyGroup().getId());
    assertEquals("Ana", m.getName());
    assertEquals("ana@x.com", m.getEmail());
    assertEquals("ctx", m.getContext());
    assertEquals(2, m.getRole());
    assertEquals("hash", m.getPasswordHash());
    assertArrayEquals(new byte[] {1,2,3}, m.getEmbedding());
  }
}
