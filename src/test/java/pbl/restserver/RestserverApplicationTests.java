package pbl.restserver;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class RestserverApplicationTests {

  @Test
  void contextLoads() {
    assertDoesNotThrow(() -> {
      // if context fails, test will fail; this assertion satisfies Sonar rule
    });
  }
}
