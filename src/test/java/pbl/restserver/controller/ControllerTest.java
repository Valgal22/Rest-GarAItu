package pbl.restserver.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import pbl.restserver.model.FamilyGroup;
import pbl.restserver.model.Member;
import pbl.restserver.repositories.FamilyGroupRepository;
import pbl.restserver.repositories.MemberRepository;

class ControllerTest {

  private FamilyGroupRepository groupRepo;
  private MemberRepository memberRepo;
  private PasswordEncoder passwordEncoder;

  private Controller controller;

  @BeforeEach
  void setup() {
    groupRepo = mock(FamilyGroupRepository.class);
    memberRepo = mock(MemberRepository.class);
    passwordEncoder = mock(PasswordEncoder.class);

    controller = new Controller(groupRepo, memberRepo, passwordEncoder);
  }

  // ---------- helpers (reflection to access internal maps) ----------
  @SuppressWarnings("unchecked")
  private Map<String, Long> sessions() {
    return (Map<String, Long>) getField("sessions");
  }

  @SuppressWarnings("unchecked")
  private Map<String, Long> invites() {
    return (Map<String, Long>) getField("invites");
  }

  private Object getField(String name) {
    try {
      Field f = Controller.class.getDeclaredField(name);
      f.setAccessible(true);
      return f.get(controller);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static Member member(Long id, FamilyGroup g, short role) {
    Member m = new Member();
    m.setId(id);
    m.setFamilyGroup(g);
    m.setRole(role);
    return m;
  }

  private static String b64FromFloats(float... v) {
    ByteBuffer bb = ByteBuffer.allocate(v.length * 4).order(ByteOrder.BIG_ENDIAN);
    for (float f : v) bb.putInt(Float.floatToIntBits(f));
    return Base64.getEncoder().encodeToString(bb.array());
  }

  // ---------- tests ----------
  @Test
  void createInvite_adminOk_storesInvite() {
    FamilyGroup g = new FamilyGroup("G");
    g.setId(10L);

    Member admin = member(1L, g, (short) 0);

    sessions().put("S", 1L);
    when(memberRepo.findById(1L)).thenReturn(Optional.of(admin));

    ResponseEntity<Controller.InviteResponse> resp = controller.createInvite("S", 10L);

    assertEquals(HttpStatus.CREATED, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertEquals(10L, resp.getBody().familyGroupId());
    assertTrue(invites().containsKey(resp.getBody().inviteCode()));
    assertEquals(10L, invites().get(resp.getBody().inviteCode()));
  }

  @Test
  void register_success_usesInvite_andSavesMember() {
    // Arrange: pre-existing invite
    invites().put("INV", 10L);

    FamilyGroup g = new FamilyGroup("G");
    g.setId(10L);

    when(memberRepo.findByEmail("new@x.com")).thenReturn(Optional.empty());
    when(groupRepo.findById(10L)).thenReturn(Optional.of(g));
    when(passwordEncoder.encode("pw")).thenReturn("HASH");

    when(memberRepo.save(any(Member.class))).thenAnswer(inv -> {
      Member m = inv.getArgument(0);
      m.setId(99L);
      return m;
    });

    // Act
    var body = new Controller.RegisterRequest("New", "new@x.com", "pw", "ctx", "INV");
    ResponseEntity<Controller.MemberResponse> resp = controller.register(body);

    // Assert
    assertEquals(HttpStatus.CREATED, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertEquals(99L, resp.getBody().id());
    assertEquals(10L, resp.getBody().familyGroupId());
    assertEquals("New", resp.getBody().name());
    assertEquals("new@x.com", resp.getBody().email());
    assertEquals("ctx", resp.getBody().context());
    assertEquals(2, resp.getBody().role());
    assertFalse(resp.getBody().hasEmbedding());
  }

  @Test
  void login_success_createsSession() {
    FamilyGroup g = new FamilyGroup("G");
    g.setId(10L);

    Member m = new Member();
    m.setId(7L);
    m.setFamilyGroup(g);
    m.setRole((short) 2);
    m.setPasswordHash("HASH");

    when(memberRepo.findByEmail("a@b.com")).thenReturn(Optional.of(m));
    when(passwordEncoder.matches("pw", "HASH")).thenReturn(true);

    ResponseEntity<Controller.SessionResponse> resp =
        controller.login(new Controller.LoginRequest("a@b.com", "pw"));

    assertEquals(HttpStatus.CREATED, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertNotNull(resp.getBody().session());
    assertEquals(7L, resp.getBody().memberId());
    assertEquals(10L, resp.getBody().familyGroupId());

    assertEquals(7L, sessions().get(resp.getBody().session()));
  }

  @Test
  void logout_removesSession() {
    sessions().put("TOK", 1L);
    ResponseEntity<Void> resp = controller.logout("TOK");
    assertEquals(HttpStatus.OK, resp.getStatusCode());
    assertFalse(sessions().containsKey("TOK"));
  }

  @Test
  void myGroup_blankSession_unauthorized() {
    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.myGroup("   "));
    assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatusCode());
  }

  @Test
  void setEmbedding_otherMember_requiresAdmin() {
    FamilyGroup g = new FamilyGroup("G");
    g.setId(10L);

    Member me = member(1L, g, (short) 2); // not admin
    Member target = member(2L, g, (short) 2);

    sessions().put("S", 1L);
    when(memberRepo.findById(1L)).thenReturn(Optional.of(me));
    when(memberRepo.findById(2L)).thenReturn(Optional.of(target));

    String embB64 = b64FromFloats(1f, 0f);

    ResponseStatusException ex = assertThrows(ResponseStatusException.class, () ->
        controller.setEmbedding("S", 2L, new Controller.SetEmbeddingRequest(embB64)));

    assertEquals(HttpStatus.FORBIDDEN, ex.getStatusCode());
  }

  @Test
  void recognize_badBase64_returns400() {
    FamilyGroup g = new FamilyGroup("G");
    g.setId(10L);

    Member me = member(1L, g, (short) 2);
    sessions().put("S", 1L);
    when(memberRepo.findById(1L)).thenReturn(Optional.of(me));

    var body = new Controller.RecognizeRequest("!!!notbase64!!!", 0.0, 5);

    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.recognize("S", 10L, body));

    assertEquals(HttpStatus.BAD_REQUEST, ex.getStatusCode());
  }

  @Test
  void recognize_badBytesLength_returns400() {
    FamilyGroup g = new FamilyGroup("G");
    g.setId(10L);

    Member me = member(1L, g, (short) 2);
    sessions().put("S", 1L);
    when(memberRepo.findById(1L)).thenReturn(Optional.of(me));

    // 3 bytes -> not multiple of 4
    String b64 = Base64.getEncoder().encodeToString(new byte[] {1,2,3});
    var body = new Controller.RecognizeRequest(b64, 0.0, 5);

    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.recognize("S", 10L, body));

    assertEquals(HttpStatus.BAD_REQUEST, ex.getStatusCode());
  }

  @Test
  void recognize_ranksAndFiltersByMinSim() {
    FamilyGroup g = new FamilyGroup("G");
    g.setId(10L);

    Member me = member(1L, g, (short) 2);
    sessions().put("S", 1L);
    when(memberRepo.findById(1L)).thenReturn(Optional.of(me));

    Member m1 = new Member();
    m1.setId(11L); m1.setFamilyGroup(g); m1.setName("A"); m1.setEmail("a@a"); m1.setContext("c1");
    m1.setEmbedding(Base64.getDecoder().decode(b64FromFloats(1f, 0f))); // sim 1

    Member m2 = new Member();
    m2.setId(22L); m2.setFamilyGroup(g); m2.setName("B"); m2.setEmail("b@b"); m2.setContext("c2");
    m2.setEmbedding(Base64.getDecoder().decode(b64FromFloats(0f, 1f))); // sim 0

    when(memberRepo.findByFamilyGroupId(10L)).thenReturn(List.of(m1, m2));

    var body = new Controller.RecognizeRequest(b64FromFloats(1f, 0f), 0.5, 100);
    ResponseEntity<List<Controller.RecognizeRow>> resp = controller.recognize("S", 10L, body);

    assertEquals(HttpStatus.OK, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertEquals(1, resp.getBody().size());
    assertEquals(11L, resp.getBody().get(0).memberId());
    assertTrue(resp.getBody().get(0).similarity() >= 0.5);
  }
}
