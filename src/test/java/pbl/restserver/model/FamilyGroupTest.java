package pbl.restserver.model;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class FamilyGroupTest {

  @Test
  void emptyConstructor_initializesNullFields() {
    FamilyGroup g = new FamilyGroup();

    assertNull(g.getId());
    assertNull(g.getName());
  }

  @Test
  void constructorAndGettersSetters_work() {
    FamilyGroup g = new FamilyGroup("Mi Familia");
    assertEquals("Mi Familia", g.getName());

    g.setId(10L);
    g.setName("Otra");
    assertEquals(10L, g.getId());
    assertEquals("Otra", g.getName());
  }
}
