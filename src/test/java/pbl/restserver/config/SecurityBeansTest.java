package pbl.restserver.config;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

class SecurityBeansTest {

  @Test
  void passwordEncoder_isBCrypt_andWorks() {
    SecurityBeans cfg = new SecurityBeans();
    PasswordEncoder enc = cfg.passwordEncoder();

    String raw = "secret";
    String hash = enc.encode(raw);

    assertNotNull(hash);
    assertNotEquals(raw, hash);
    assertTrue(enc.matches(raw, hash));
    assertFalse(enc.matches("wrong", hash));
  }
}
