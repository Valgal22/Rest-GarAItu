package pbl.restserver.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
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

  private static final short ROLE_ADMIN = 0;
  private static final short ROLE_PATIENT = 1;
  private static final short ROLE_MEMBER = 2;

  @BeforeEach
  void setup() {
    groupRepo = mock(FamilyGroupRepository.class);
    memberRepo = mock(MemberRepository.class);
    passwordEncoder = mock(PasswordEncoder.class);
    controller = new Controller(groupRepo, memberRepo, passwordEncoder);
  }

  // ---------- reflection helpers ----------
  @SuppressWarnings("unchecked")
  private Map<String, Long> sessions() {
    return (Map<String, Long>) getField("sessions");
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

  // ---------- domain helpers ----------
  private static FamilyGroup group(long id, String name) {
    FamilyGroup g = new FamilyGroup(name);
    g.setId(id);
    return g;
  }

  private static Member member(Long id, FamilyGroup g, short role) {
    Member m = new Member();
    m.setId(id);
    m.setFamilyGroup(g);
    m.setRole(role);
    m.setName("N" + id);
    m.setEmail("e" + id + "@x.com");
    m.setContext("ctx" + id);
    m.setPasswordHash("HASH");
    return m;
  }

  // IMPORTANT: controller decodifica floats con LITTLE_ENDIAN
  private static String b64FromFloats(float... v) {
    ByteBuffer bb = ByteBuffer.allocate(v.length * 4).order(ByteOrder.LITTLE_ENDIAN);
    for (float f : v) bb.putFloat(f);
    return Base64.getEncoder().encodeToString(bb.array());
  }

  private static byte[] bytesFromFloats(float... v) {
    return Base64.getDecoder().decode(b64FromFloats(v));
  }

  private void bindSession(String token, Member m) {
    sessions().put(token, m.getId());
    when(memberRepo.findById(m.getId())).thenReturn(Optional.of(m));
  }

  private static void assertStatus(ResponseStatusException ex, HttpStatus expected) {
    assertEquals(expected, ex.getStatusCode());
  }

  // -------------------------
  // myGroup
  // -------------------------
  static Stream<String> invalidSessions() {
    return Stream.of("   ", "NOPE");
  }

  @Test
  void myGroup_nullSession_unauthorized() {
    ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> controller.myGroup(null));
    assertStatus(ex, HttpStatus.UNAUTHORIZED);
  }

  @ParameterizedTest
  @MethodSource("invalidSessions")
  void myGroup_invalidSession_unauthorized(String sessionId) {
    ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> controller.myGroup(sessionId));
    assertStatus(ex, HttpStatus.UNAUTHORIZED);
  }

  @Test
  void myGroup_tokenMemberMissing_unauthorized() {
    sessions().put("S", 999L);
    when(memberRepo.findById(999L)).thenReturn(Optional.empty());

    ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> controller.myGroup("S"));
    assertStatus(ex, HttpStatus.UNAUTHORIZED);
  }

  @Test
  void myGroup_ok_returnsGroupResponse() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    ResponseEntity<Controller.GroupResponse> resp = controller.myGroup("S");
    assertEquals(HttpStatus.OK, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertEquals(10L, resp.getBody().id());
    assertEquals("G", resp.getBody().name());
  }

  // -------------------------
  // getMembers
  // -------------------------
  @Test
  void getMembers_forbidden_otherGroup() {
    FamilyGroup g1 = group(10L, "G1");
    FamilyGroup g2 = group(20L, "G2");
    Long g2Id = g2.getId();

    Member me = member(1L, g1, ROLE_MEMBER);
    bindSession("S", me);

    ResponseStatusException ex = assertThrows(
        ResponseStatusException.class,
        () -> controller.getMembers("S", g2Id));

    assertStatus(ex, HttpStatus.FORBIDDEN);
  }

  @Test
  void getMembers_ok_mapsMembers_andHasEmbeddingTrueFalse() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    Member m1 = member(11L, g, ROLE_MEMBER);
    m1.setEmbedding(null);

    Member m2 = member(22L, g, ROLE_PATIENT);
    m2.setEmbedding(new byte[] { 1, 2, 3 });

    when(memberRepo.findByFamilyGroupId(10L)).thenReturn(List.of(m1, m2));

    ResponseEntity<List<Controller.MemberResponse>> resp = controller.getMembers("S", 10L);
    assertEquals(HttpStatus.OK, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertEquals(2, resp.getBody().size());
    assertFalse(resp.getBody().get(0).hasEmbedding());
    assertTrue(resp.getBody().get(1).hasEmbedding());
  }

  // -------------------------
  // createMemory
  // -------------------------
  @Test
  void createMemory_badRequest_userNotInGroup() {
    Member me = member(1L, null, ROLE_MEMBER);
    me.setFamilyGroup(null);
    bindSession("S", me);

    Controller.CreateMemoryRequest req = new Controller.CreateMemoryRequest("m", "c", b64FromFloats(1f, 0f));

    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.createMemory("S", req));
    assertStatus(ex, HttpStatus.BAD_REQUEST);
  }

  @Test
  void createMemory_badRequest_nameRequired() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    Controller.CreateMemoryRequest req = new Controller.CreateMemoryRequest("   ", "ctx", b64FromFloats(1f, 0f));

    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.createMemory("S", req));
    assertStatus(ex, HttpStatus.BAD_REQUEST);
  }

  @Test
  void createMemory_badRequest_embeddingRequired() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    Controller.CreateMemoryRequest req = new Controller.CreateMemoryRequest("Name", "ctx", "   ");

    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.createMemory("S", req));
    assertStatus(ex, HttpStatus.BAD_REQUEST);
  }

  @Test
  void createMemory_ok_createsPassiveMemberWithEmbedding() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    when(memberRepo.save(any(Member.class))).thenAnswer(inv -> {
      Member m = inv.getArgument(0);
      m.setId(88L);
      return m;
    });

    Controller.CreateMemoryRequest req = new Controller.CreateMemoryRequest("Memory", "ctx", b64FromFloats(1f, 0f));
    ResponseEntity<Controller.MemberResponse> resp = controller.createMemory("S", req);

    assertEquals(HttpStatus.CREATED, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertEquals(88L, resp.getBody().id());
    assertTrue(resp.getBody().hasEmbedding());
    assertEquals(10L, resp.getBody().familyGroupId());
  }

  // -------------------------
  // createGroup
  // -------------------------
  @Test
  void createGroup_forbidden_notAdmin() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    Controller.CreateGroupRequest req = new Controller.CreateGroupRequest("NewGroup");

    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.createGroup("S", req));
    assertStatus(ex, HttpStatus.FORBIDDEN);
  }

  @Test
  void createGroup_ok_adminCreatesAndMemberUpdated() {
    FamilyGroup oldGroup = group(10L, "OLD");
    Member admin = member(1L, oldGroup, ROLE_ADMIN);
    bindSession("S", admin);

    when(groupRepo.save(any(FamilyGroup.class))).thenAnswer(inv -> {
      FamilyGroup g = inv.getArgument(0);
      g.setId(99L);
      return g;
    });

    when(memberRepo.save(any(Member.class))).thenAnswer(inv -> inv.getArgument(0));

    Controller.CreateGroupRequest req = new Controller.CreateGroupRequest("NewGroup");
    ResponseEntity<Controller.GroupResponse> resp = controller.createGroup("S", req);

    assertEquals(HttpStatus.CREATED, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertEquals(99L, resp.getBody().id());
    assertEquals("NewGroup", resp.getBody().name());
  }

  // -------------------------
  // joinGroup (NOW: uses DB inviteCode)
  // -------------------------
  @Test
  void joinGroup_badRequest_inviteRequired() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    Controller.JoinGroupRequest req = new Controller.JoinGroupRequest("   ");

    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.joinGroup("S", req));
    assertStatus(ex, HttpStatus.BAD_REQUEST);
  }

  @Test
  void joinGroup_badRequest_invalidInviteCode() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    when(groupRepo.findByInviteCode("INVALID")).thenReturn(Optional.empty());

    Controller.JoinGroupRequest req = new Controller.JoinGroupRequest("INVALID");

    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.joinGroup("S", req));
    assertStatus(ex, HttpStatus.BAD_REQUEST);
  }

  @Test
  void joinGroup_ok_updatesMemberGroup() {
    FamilyGroup g = group(10L, "G");
    FamilyGroup g2 = group(20L, "G2");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    when(groupRepo.findByInviteCode("CODE")).thenReturn(Optional.of(g2));
    when(memberRepo.save(any(Member.class))).thenAnswer(inv -> inv.getArgument(0));

    Controller.JoinGroupRequest req = new Controller.JoinGroupRequest("CODE");
    ResponseEntity<Controller.MemberResponse> resp = controller.joinGroup("S", req);

    assertEquals(HttpStatus.OK, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertEquals(20L, resp.getBody().familyGroupId());
  }

  // -------------------------
  // createInvite (NOW: stored in FamilyGroup.inviteCode)
  // -------------------------
  @Test
  void createInvite_forbidden_notAdmin() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.createInvite("S", 10L));
    assertStatus(ex, HttpStatus.FORBIDDEN);
  }

  @Test
  void createInvite_forbidden_otherGroup_evenIfAdmin() {
    FamilyGroup g1 = group(10L, "G1");
    FamilyGroup g2 = group(20L, "G2");
    Long g2Id = g2.getId();

    Member admin = member(1L, g1, ROLE_ADMIN);
    bindSession("S", admin);

    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.createInvite("S", g2Id));
    assertStatus(ex, HttpStatus.FORBIDDEN);
  }

  @Test
  void createInvite_adminOk_generatesAndPersistsInviteCode_ifMissing() {
    FamilyGroup g = group(10L, "G");
    // Si tu entidad tiene inviteCode, dejamos que esté vacío para forzar generación
    g.setInviteCode(null);

    Member admin = member(1L, g, ROLE_ADMIN);
    bindSession("S", admin);

    when(groupRepo.save(any(FamilyGroup.class))).thenAnswer(inv -> inv.getArgument(0));

    ResponseEntity<Controller.InviteResponse> resp = controller.createInvite("S", 10L);
    assertEquals(HttpStatus.CREATED, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertEquals(10L, resp.getBody().familyGroupId());
    assertNotNull(resp.getBody().inviteCode());
    assertFalse(resp.getBody().inviteCode().isBlank());

    // Se guarda en el group (persistente)
    assertEquals(resp.getBody().inviteCode(), g.getInviteCode());
    verify(groupRepo, atLeastOnce()).save(any(FamilyGroup.class));
  }

  @Test
  void createInvite_adminOk_returnsExistingCode_ifAlreadyPresent() {
    FamilyGroup g = group(10L, "G");
    g.setInviteCode("EXIST123");

    Member admin = member(1L, g, ROLE_ADMIN);
    bindSession("S", admin);

    ResponseEntity<Controller.InviteResponse> resp = controller.createInvite("S", 10L);
    assertEquals(HttpStatus.CREATED, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertEquals("EXIST123", resp.getBody().inviteCode());

    // No hace falta guardar si ya existe
    verify(groupRepo, never()).save(any(FamilyGroup.class));
  }

  // -------------------------
  // register
  // -------------------------
  @Test
  void register_badRequest_missingFields() {
    Controller.RegisterRequest r1 = new Controller.RegisterRequest("", "a@b.com", "pw", "ctx", ROLE_MEMBER, null);
    ResponseStatusException ex1 = assertThrows(ResponseStatusException.class, () -> controller.register(r1));
    assertStatus(ex1, HttpStatus.BAD_REQUEST);

    Controller.RegisterRequest r2 = new Controller.RegisterRequest("N", " ", "pw", "ctx", ROLE_MEMBER, null);
    ResponseStatusException ex2 = assertThrows(ResponseStatusException.class, () -> controller.register(r2));
    assertStatus(ex2, HttpStatus.BAD_REQUEST);

    Controller.RegisterRequest r3 = new Controller.RegisterRequest("N", "a@b.com", "", "ctx", ROLE_MEMBER, null);
    ResponseStatusException ex3 = assertThrows(ResponseStatusException.class, () -> controller.register(r3));
    assertStatus(ex3, HttpStatus.BAD_REQUEST);
  }

  @Test
  void register_conflict_emailExists() {
    when(memberRepo.findByEmail("a@b.com")).thenReturn(Optional.of(new Member()));
    Controller.RegisterRequest req = new Controller.RegisterRequest("N", "a@b.com", "pw", "ctx", ROLE_MEMBER, null);

    ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> controller.register(req));
    assertStatus(ex, HttpStatus.CONFLICT);
  }

  @Test
  void register_success_savesMember() {
    when(memberRepo.findByEmail("new@x.com")).thenReturn(Optional.empty());
    when(passwordEncoder.encode("pw")).thenReturn("HASH");

    when(memberRepo.save(any(Member.class))).thenAnswer(inv -> {
      Member m = inv.getArgument(0);
      m.setId(99L);
      return m;
    });

    Controller.RegisterRequest req = new Controller.RegisterRequest("New", "new@x.com", "pw", "ctx", ROLE_MEMBER, null);
    ResponseEntity<Controller.MemberResponse> resp = controller.register(req);

    assertEquals(HttpStatus.CREATED, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertEquals(99L, resp.getBody().id());
    assertFalse(resp.getBody().hasEmbedding());
  }

  // -------------------------
  // login
  // -------------------------
  @Test
  void login_badRequest_missingFields() {
    Controller.LoginRequest r1 = new Controller.LoginRequest("", "pw");
    ResponseStatusException ex1 = assertThrows(ResponseStatusException.class, () -> controller.login(r1));
    assertStatus(ex1, HttpStatus.BAD_REQUEST);

    Controller.LoginRequest r2 = new Controller.LoginRequest("a@b.com", " ");
    ResponseStatusException ex2 = assertThrows(ResponseStatusException.class, () -> controller.login(r2));
    assertStatus(ex2, HttpStatus.BAD_REQUEST);
  }

  @Test
  void login_unauthorized_userNotFound() {
    when(memberRepo.findByEmail("a@b.com")).thenReturn(Optional.empty());

    Controller.LoginRequest req = new Controller.LoginRequest("a@b.com", "pw");
    ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> controller.login(req));
    assertStatus(ex, HttpStatus.UNAUTHORIZED);
  }

  @Test
  void login_unauthorized_passwordHashNull() {
    FamilyGroup g = group(10L, "G");
    Member m = member(7L, g, ROLE_MEMBER);
    m.setPasswordHash(null);

    when(memberRepo.findByEmail("a@b.com")).thenReturn(Optional.of(m));

    Controller.LoginRequest req = new Controller.LoginRequest("a@b.com", "pw");
    ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> controller.login(req));
    assertStatus(ex, HttpStatus.UNAUTHORIZED);
  }

  @Test
  void login_unauthorized_passwordMismatch() {
    FamilyGroup g = group(10L, "G");
    Member m = member(7L, g, ROLE_MEMBER);
    m.setPasswordHash("HASH");

    when(memberRepo.findByEmail("a@b.com")).thenReturn(Optional.of(m));
    when(passwordEncoder.matches("pw", "HASH")).thenReturn(false);

    Controller.LoginRequest req = new Controller.LoginRequest("a@b.com", "pw");
    ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> controller.login(req));
    assertStatus(ex, HttpStatus.UNAUTHORIZED);
  }

  @Test
  void login_success_createsSession() {
    FamilyGroup g = group(10L, "G");
    Member m = member(7L, g, ROLE_MEMBER);
    m.setPasswordHash("HASH");

    when(memberRepo.findByEmail("a@b.com")).thenReturn(Optional.of(m));
    when(passwordEncoder.matches("pw", "HASH")).thenReturn(true);

    Controller.LoginRequest req = new Controller.LoginRequest("a@b.com", "pw");
    ResponseEntity<Controller.SessionResponse> resp = controller.login(req);

    assertEquals(HttpStatus.CREATED, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertNotNull(resp.getBody().session());
    assertEquals(7L, sessions().get(resp.getBody().session()));
  }

  // -------------------------
  // logout
  // -------------------------
  @Test
  void logout_removesSession_evenIfMissing() {
    sessions().put("TOK", 1L);

    ResponseEntity<Void> resp1 = controller.logout("TOK");
    assertEquals(HttpStatus.OK, resp1.getStatusCode());
    assertFalse(sessions().containsKey("TOK"));

    ResponseEntity<Void> resp2 = controller.logout("NOPE");
    assertEquals(HttpStatus.OK, resp2.getStatusCode());
  }

  // -------------------------
  // setEmbedding
  // -------------------------
  @Test
  void setEmbedding_notFound_targetMember() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_ADMIN);
    bindSession("S", me);

    when(memberRepo.findById(99L)).thenReturn(Optional.empty());

    Controller.SetEmbeddingRequest req = new Controller.SetEmbeddingRequest(b64FromFloats(1f, 0f));
    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.setEmbedding("S", 99L, req));
    assertStatus(ex, HttpStatus.NOT_FOUND);
  }

  @Test
  void setEmbedding_forbidden_otherGroup() {
    FamilyGroup g1 = group(10L, "G1");
    FamilyGroup g2 = group(20L, "G2");

    Member me = member(1L, g1, ROLE_ADMIN);
    Member target = member(2L, g2, ROLE_MEMBER);

    bindSession("S", me);
    when(memberRepo.findById(2L)).thenReturn(Optional.of(target));

    Controller.SetEmbeddingRequest req = new Controller.SetEmbeddingRequest(b64FromFloats(1f, 0f));
    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.setEmbedding("S", 2L, req));
    assertStatus(ex, HttpStatus.FORBIDDEN);
  }

  @Test
  void setEmbedding_otherMember_requiresAdmin() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    Member target = member(2L, g, ROLE_MEMBER);

    bindSession("S", me);
    when(memberRepo.findById(2L)).thenReturn(Optional.of(target));

    Controller.SetEmbeddingRequest req = new Controller.SetEmbeddingRequest(b64FromFloats(1f, 0f));
    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.setEmbedding("S", 2L, req));
    assertStatus(ex, HttpStatus.FORBIDDEN);
  }

  @Test
  void setEmbedding_badRequest_embeddingRequired_blankBase64() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_ADMIN);
    Member target = member(2L, g, ROLE_MEMBER);

    bindSession("S", me);
    when(memberRepo.findById(2L)).thenReturn(Optional.of(target));

    Controller.SetEmbeddingRequest req = new Controller.SetEmbeddingRequest("   ");
    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.setEmbedding("S", 2L, req));
    assertStatus(ex, HttpStatus.BAD_REQUEST);
  }

  @Test
  void setEmbedding_badRequest_badBase64() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_ADMIN);
    Member target = member(2L, g, ROLE_MEMBER);

    bindSession("S", me);
    when(memberRepo.findById(2L)).thenReturn(Optional.of(target));

    Controller.SetEmbeddingRequest req = new Controller.SetEmbeddingRequest("!!!notbase64!!!");
    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.setEmbedding("S", 2L, req));
    assertStatus(ex, HttpStatus.BAD_REQUEST);
  }

  @Test
  void setEmbedding_ok_self_noAdminNeeded_savesAndReturns() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);

    bindSession("S", me);
    when(memberRepo.findById(1L)).thenReturn(Optional.of(me));
    when(memberRepo.save(any(Member.class))).thenAnswer(inv -> inv.getArgument(0));

    String embB64 = b64FromFloats(1f, 0f);
    Controller.SetEmbeddingRequest req = new Controller.SetEmbeddingRequest(embB64);

    ResponseEntity<Controller.MemberResponse> resp = controller.setEmbedding("S", 1L, req);
    assertEquals(HttpStatus.OK, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertTrue(resp.getBody().hasEmbedding());
  }

  @Test
  void setEmbedding_ok_adminUpdatesOtherMember_savesAndReturns() {
    FamilyGroup g = group(10L, "G");
    Member admin = member(1L, g, ROLE_ADMIN);
    Member target = member(2L, g, ROLE_MEMBER);

    bindSession("S", admin);
    when(memberRepo.findById(2L)).thenReturn(Optional.of(target));
    when(memberRepo.save(any(Member.class))).thenAnswer(inv -> inv.getArgument(0));

    Controller.SetEmbeddingRequest req = new Controller.SetEmbeddingRequest(b64FromFloats(1f, 0f));
    ResponseEntity<Controller.MemberResponse> resp = controller.setEmbedding("S", 2L, req);

    assertEquals(HttpStatus.OK, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertTrue(resp.getBody().hasEmbedding());
  }

  // -------------------------
  // recognize
  // -------------------------
  @Test
  void recognize_forbidden_otherGroup() {
    FamilyGroup g1 = group(10L, "G1");
    FamilyGroup g2 = group(20L, "G2");
    Long g2Id = g2.getId();

    Member me = member(1L, g1, ROLE_MEMBER);
    bindSession("S", me);

    Controller.RecognizeRequest req = new Controller.RecognizeRequest(b64FromFloats(1f, 0f), 0.0, 5);

    ResponseStatusException ex = assertThrows(
        ResponseStatusException.class,
        () -> controller.recognize("S", g2Id, req));

    assertStatus(ex, HttpStatus.FORBIDDEN);
  }

  @Test
  void recognize_badRequest_embeddingRequired_blank() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    Controller.RecognizeRequest req = new Controller.RecognizeRequest("   ", 0.0, 5);
    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.recognize("S", 10L, req));
    assertStatus(ex, HttpStatus.BAD_REQUEST);
  }

  @Test
  void recognize_badRequest_badBase64() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    Controller.RecognizeRequest req = new Controller.RecognizeRequest("!!!notbase64!!!", 0.0, 5);
    ResponseStatusException ex = assertThrows(ResponseStatusException.class,
        () -> controller.recognize("S", 10L, req));
    assertStatus(ex, HttpStatus.BAD_REQUEST);
  }

  @Test
  void recognize_bytesLengthNotMultipleOf4_isNotRejected_returnsOkEmpty() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    String b64 = Base64.getEncoder().encodeToString(new byte[] { 1, 2, 3 }); // 3 bytes -> 0 floats
    when(memberRepo.findByFamilyGroupId(10L)).thenReturn(List.of());

    Controller.RecognizeRequest req = new Controller.RecognizeRequest(b64, 0.0, 5);
    ResponseEntity<List<Controller.RecognizeRow>> resp = controller.recognize("S", 10L, req);

    assertEquals(HttpStatus.OK, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertTrue(resp.getBody().isEmpty());
  }

  @Test
  void recognize_cosineBranches_filteredOut() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    Member m1 = member(11L, g, ROLE_MEMBER);
    m1.setEmbedding(bytesFromFloats(1f, 0f, 0f)); // dim 3

    Member m2 = member(22L, g, ROLE_MEMBER);
    m2.setEmbedding(bytesFromFloats(0f, 0f)); // dim 2

    when(memberRepo.findByFamilyGroupId(10L)).thenReturn(List.of(m1, m2));

    Controller.RecognizeRequest req = new Controller.RecognizeRequest(b64FromFloats(1f, 0f), 0.0, 5);
    ResponseEntity<List<Controller.RecognizeRow>> resp = controller.recognize("S", 10L, req);

    assertEquals(HttpStatus.OK, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertTrue(resp.getBody().isEmpty());
  }

  @Test
  void recognize_skipsMembersWithoutEmbedding() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    Member m1 = member(11L, g, ROLE_MEMBER);
    m1.setEmbedding(null);

    Member m2 = member(22L, g, ROLE_MEMBER);
    m2.setEmbedding(new byte[0]);

    when(memberRepo.findByFamilyGroupId(10L)).thenReturn(List.of(m1, m2));

    Controller.RecognizeRequest req = new Controller.RecognizeRequest(b64FromFloats(1f, 0f), 0.0, 5);
    ResponseEntity<List<Controller.RecognizeRow>> resp = controller.recognize("S", 10L, req);

    assertEquals(HttpStatus.OK, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertTrue(resp.getBody().isEmpty());
  }

  @Test
  void recognize_ranksFiltersByMinSim_andTopIsClamped() {
    FamilyGroup g = group(10L, "G");
    Member me = member(1L, g, ROLE_MEMBER);
    bindSession("S", me);

    Member mA = member(11L, g, ROLE_MEMBER);
    mA.setName("A");
    mA.setEmail("a@a");
    mA.setContext("c1");
    mA.setEmbedding(bytesFromFloats(1f, 0f));

    Member mB = member(22L, g, ROLE_MEMBER);
    mB.setName("B");
    mB.setEmail("b@b");
    mB.setContext("c2");
    mB.setEmbedding(bytesFromFloats(0f, 1f));

    when(memberRepo.findByFamilyGroupId(10L)).thenReturn(List.of(mA, mB));

    Controller.RecognizeRequest req1 = new Controller.RecognizeRequest(b64FromFloats(1f, 0f), 0.5, 1000);
    ResponseEntity<List<Controller.RecognizeRow>> resp1 = controller.recognize("S", 10L, req1);

    assertEquals(HttpStatus.OK, resp1.getStatusCode());
    assertNotNull(resp1.getBody());
    assertEquals(1, resp1.getBody().size());
    assertEquals(11L, resp1.getBody().get(0).memberId());

    Controller.RecognizeRequest req2 = new Controller.RecognizeRequest(b64FromFloats(1f, 0f), -1.0, 0);
    ResponseEntity<List<Controller.RecognizeRow>> resp2 = controller.recognize("S", 10L, req2);

    assertEquals(HttpStatus.OK, resp2.getStatusCode());
    assertNotNull(resp2.getBody());
    assertEquals(1, resp2.getBody().size());
  }

  // -------------------------
// deleteMember
// -------------------------
@Test
void deleteMember_forbidden_notAdmin() {
  FamilyGroup g = group(10L, "G");
  Member me = member(1L, g, ROLE_MEMBER);
  bindSession("S", me);

  ResponseStatusException ex = assertThrows(ResponseStatusException.class,
      () -> controller.deleteMember("S", 10L, 2L));
  assertStatus(ex, HttpStatus.FORBIDDEN);
}

@Test
void deleteMember_forbidden_otherGroup() {
  FamilyGroup g1 = group(10L, "G1");
  Member me = member(1L, g1, ROLE_ADMIN);
  bindSession("S", me);

  ResponseStatusException ex = assertThrows(ResponseStatusException.class,
      () -> controller.deleteMember("S", 20L, 2L));
  assertStatus(ex, HttpStatus.FORBIDDEN);
}

@Test
void deleteMember_notFound_targetMissing() {
  FamilyGroup g = group(10L, "G");
  Member me = member(1L, g, ROLE_ADMIN);
  bindSession("S", me);

  when(memberRepo.findById(99L)).thenReturn(Optional.empty());

  ResponseStatusException ex = assertThrows(ResponseStatusException.class,
      () -> controller.deleteMember("S", 10L, 99L));
  assertStatus(ex, HttpStatus.NOT_FOUND);
}

@Test
void deleteMember_badRequest_targetNotInGroup() {
  FamilyGroup g = group(10L, "G");
  FamilyGroup other = group(20L, "O");
  Member me = member(1L, g, ROLE_ADMIN);
  Member target = member(2L, other, ROLE_MEMBER);

  bindSession("S", me);
  when(memberRepo.findById(2L)).thenReturn(Optional.of(target));

  ResponseStatusException ex = assertThrows(ResponseStatusException.class,
      () -> controller.deleteMember("S", 10L, 2L));
  assertStatus(ex, HttpStatus.BAD_REQUEST);
}

@Test
void deleteMember_ok_unlinksMember_andReturnsNoContent() {
  FamilyGroup g = group(10L, "G");
  Member me = member(1L, g, ROLE_ADMIN);
  Member target = member(2L, g, ROLE_MEMBER);

  bindSession("S", me);
  when(memberRepo.findById(2L)).thenReturn(Optional.of(target));
  when(memberRepo.save(any(Member.class))).thenAnswer(inv -> inv.getArgument(0));

  ResponseEntity<Void> resp = controller.deleteMember("S", 10L, 2L);

  assertEquals(HttpStatus.NO_CONTENT, resp.getStatusCode());
  assertNull(target.getFamilyGroup());
  verify(memberRepo).save(target);
}

// -------------------------
// getGroupCodeByName
// -------------------------
@Test
void getGroupCodeByName_badRequest_nameBlank() {
  FamilyGroup g = group(10L, "G");
  Member me = member(1L, g, ROLE_MEMBER);
  bindSession("S", me);

  ResponseStatusException ex = assertThrows(ResponseStatusException.class,
      () -> controller.getGroupCodeByName("S", "   "));
  assertStatus(ex, HttpStatus.BAD_REQUEST);
}

@Test
void getGroupCodeByName_notFound_groupMissing() {
  FamilyGroup g = group(10L, "G");
  Member me = member(1L, g, ROLE_MEMBER);
  bindSession("S", me);

  when(groupRepo.findByName("X")).thenReturn(Optional.empty());

  ResponseStatusException ex = assertThrows(ResponseStatusException.class,
      () -> controller.getGroupCodeByName("S", "X"));
  assertStatus(ex, HttpStatus.NOT_FOUND);
}

@Test
void getGroupCodeByName_ok_returnsExistingCode_withoutSaving() {
  FamilyGroup g = group(10L, "G");
  g.setInviteCode("EXIST123");
  Member me = member(1L, group(99L, "ANY"), ROLE_MEMBER);
  bindSession("S", me);

  when(groupRepo.findByName("G")).thenReturn(Optional.of(g));

  ResponseEntity<Controller.InviteResponse> resp = controller.getGroupCodeByName("S", "G");

  assertEquals(HttpStatus.OK, resp.getStatusCode());
  assertNotNull(resp.getBody());
  assertEquals("EXIST123", resp.getBody().inviteCode());
  assertEquals(10L, resp.getBody().familyGroupId());
  verify(groupRepo, never()).save(any());
}

@Test
void getGroupCodeByName_ok_generatesAndSaves_whenMissing() {
  FamilyGroup g = group(10L, "G");
  g.setInviteCode(null);
  Member me = member(1L, group(99L, "ANY"), ROLE_MEMBER);
  bindSession("S", me);

  when(groupRepo.findByName("G")).thenReturn(Optional.of(g));
  when(groupRepo.save(any(FamilyGroup.class))).thenAnswer(inv -> inv.getArgument(0));

  ResponseEntity<Controller.InviteResponse> resp = controller.getGroupCodeByName("S", "G");

  assertEquals(HttpStatus.OK, resp.getStatusCode());
  assertNotNull(resp.getBody());
  assertNotNull(resp.getBody().inviteCode());
  assertFalse(resp.getBody().inviteCode().isBlank());
  assertEquals(g.getInviteCode(), resp.getBody().inviteCode());
  verify(groupRepo).save(g);
}

// -------------------------
// updateMember
// -------------------------
@Test
void updateMember_notFound_targetMissing() {
  FamilyGroup g = group(10L, "G");
  Member me = member(1L, g, ROLE_MEMBER);
  bindSession("S", me);

  when(memberRepo.findById(2L)).thenReturn(Optional.empty());

  Controller.UpdateMemberRequest req = new Controller.UpdateMemberRequest("X", "Y");
  ResponseStatusException ex = assertThrows(ResponseStatusException.class,
      () -> controller.updateMember("S", 2L, req));
  assertStatus(ex, HttpStatus.NOT_FOUND);
}

@Test
void updateMember_forbidden_notSelf_notAdmin() {
  FamilyGroup g = group(10L, "G");
  Member me = member(1L, g, ROLE_MEMBER);
  Member target = member(2L, g, ROLE_MEMBER);
  bindSession("S", me);

  when(memberRepo.findById(2L)).thenReturn(Optional.of(target));

  Controller.UpdateMemberRequest req = new Controller.UpdateMemberRequest("X", "Y");
  ResponseStatusException ex = assertThrows(ResponseStatusException.class,
      () -> controller.updateMember("S", 2L, req));
  assertStatus(ex, HttpStatus.FORBIDDEN);
}

@Test
void updateMember_ok_self_updatesNameAndContext() {
  FamilyGroup g = group(10L, "G");
  Member me = member(1L, g, ROLE_MEMBER);
  bindSession("S", me);

  when(memberRepo.findById(1L)).thenReturn(Optional.of(me));
  when(memberRepo.save(any(Member.class))).thenAnswer(inv -> inv.getArgument(0));

  Controller.UpdateMemberRequest req = new Controller.UpdateMemberRequest("Nuevo", "");
  ResponseEntity<Controller.MemberResponse> resp = controller.updateMember("S", 1L, req);

  assertEquals(HttpStatus.OK, resp.getStatusCode());
  assertEquals("Nuevo", me.getName());
  assertEquals("", me.getContext());
}

@Test
void updateMember_ok_admin_sameGroup_updatesOtherMember() {
  FamilyGroup g = group(10L, "G");
  Member admin = member(1L, g, ROLE_ADMIN);
  Member target = member(2L, g, ROLE_MEMBER);

  bindSession("S", admin);
  when(memberRepo.findById(2L)).thenReturn(Optional.of(target));
  when(memberRepo.save(any(Member.class))).thenAnswer(inv -> inv.getArgument(0));

  Controller.UpdateMemberRequest req = new Controller.UpdateMemberRequest("T", "C");
  ResponseEntity<Controller.MemberResponse> resp = controller.updateMember("S", 2L, req);

  assertEquals(HttpStatus.OK, resp.getStatusCode());
  assertEquals("T", target.getName());
  assertEquals("C", target.getContext());
}

@Test
void updateMember_nameBlank_doesNotOverwriteName_contextNull_doesNotTouchContext() {
  FamilyGroup g = group(10L, "G");
  Member me = member(1L, g, ROLE_MEMBER);
  me.setName("KEEP");
  me.setContext("CTX");
  bindSession("S", me);

  when(memberRepo.findById(1L)).thenReturn(Optional.of(me));
  when(memberRepo.save(any(Member.class))).thenAnswer(inv -> inv.getArgument(0));

  Controller.UpdateMemberRequest req = new Controller.UpdateMemberRequest("   ", null);
  controller.updateMember("S", 1L, req);

  assertEquals("KEEP", me.getName());
  assertEquals("CTX", me.getContext());
}

// -------------------------
// getGroupAdmin
// -------------------------
@Test
void getGroupAdmin_notFound_whenNoAdmin() {
  FamilyGroup g = group(10L, "G");
  Member me = member(1L, g, ROLE_MEMBER);
  bindSession("S", me);

  when(memberRepo.findByFamilyGroupId(10L)).thenReturn(List.of(member(2L, g, ROLE_MEMBER)));

  ResponseStatusException ex = assertThrows(ResponseStatusException.class,
      () -> controller.getGroupAdmin("S", 10L));
  assertStatus(ex, HttpStatus.NOT_FOUND);
}

@Test
void getGroupAdmin_ok_returnsFirstAdmin() {
  FamilyGroup g = group(10L, "G");
  Member me = member(1L, g, ROLE_MEMBER);
  bindSession("S", me);

  Member admin = member(2L, g, ROLE_ADMIN);
  when(memberRepo.findByFamilyGroupId(10L)).thenReturn(List.of(member(3L, g, ROLE_MEMBER), admin));

  ResponseEntity<Controller.MemberResponse> resp = controller.getGroupAdmin("S", 10L);
  assertEquals(HttpStatus.OK, resp.getStatusCode());
  assertNotNull(resp.getBody());
  assertEquals(2L, resp.getBody().id());
}

// -------------------------
// setTelegramId
// -------------------------
@Test
void setTelegramId_ok_updatesAndSaves() {
  FamilyGroup g = group(10L, "G");
  Member me = member(1L, g, ROLE_MEMBER);
  bindSession("S", me);

  when(memberRepo.save(any(Member.class))).thenAnswer(inv -> inv.getArgument(0));

  ResponseEntity<Void> resp = controller.setTelegramId("S", "12345");
  assertEquals(HttpStatus.OK, resp.getStatusCode());
  assertEquals("12345", me.getTelegramChatId());
  verify(memberRepo).save(me);
}

}
