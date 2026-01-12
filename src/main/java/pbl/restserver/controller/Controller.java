package pbl.restserver.controller;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import pbl.restserver.model.FamilyGroup;
import pbl.restserver.model.Member;
import pbl.restserver.repositories.FamilyGroupRepository;
import pbl.restserver.repositories.MemberRepository;

@RestController
@RequestMapping("/garAItu")
public class Controller {
  private static final Logger logger = LoggerFactory.getLogger(Controller.class);

  // Roles: admin 0, patient 1, member 2
  private static final short ROLE_ADMIN = 0;
  private static final short ROLE_PATIENT = 1;
  private static final short ROLE_MEMBER = 2;

  private final FamilyGroupRepository groupRepo;
  private final MemberRepository memberRepo;
  private final PasswordEncoder passwordEncoder;

  // token -> memberId
  private final Map<String, Long> sessions = new ConcurrentHashMap<>();

  // inviteCode -> groupId (en memoria) - REMOVED, now using DB
  // private final Map<String, Long> invites = new ConcurrentHashMap<>();

  public Controller(FamilyGroupRepository groupRepo,
      MemberRepository memberRepo,
      PasswordEncoder passwordEncoder) {
    this.groupRepo = groupRepo;
    this.memberRepo = memberRepo;
    this.passwordEncoder = passwordEncoder;
  }

  // -------------------------
  // DTOs
  // -------------------------
  public static record RegisterRequest(String name, String email, String password, String context, short role) {
  }

  public static record LoginRequest(String email, String password) {
  }

  public static record SessionResponse(String session, Long memberId, Long familyGroupId, short role) {
  }

  public static record GroupResponse(Long id, String name) {
  }

  public static record CreateGroupRequest(String name) {
  }

  public static record JoinGroupRequest(String inviteCode) {
  }

  public static record MemberResponse(Long id, Long familyGroupId, String name, String email, String context,
      short role, boolean hasEmbedding) {
  }

  public static record InviteResponse(String inviteCode, Long familyGroupId) {
  }

  public static record SetEmbeddingRequest(String embeddingBase64) {
  }

  public static record RecognizeRequest(
      String embeddingBase64,
      @RequestParam(required = false, defaultValue = "0.0") double minSim,
      @RequestParam(required = false, defaultValue = "5") int top) {
  }

  public static record RecognizeRow(Long memberId, String name, String email, String context, double similarity) {
  }

  public static record CreateMemoryRequest(String name, String context, String embeddingBase64) {
  }

  // -------------------------
  // Helpers
  // -------------------------
  private Member requireMemberFromSession(String sessionId) {
    if (sessionId == null || sessionId.isBlank())
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No session");

    Long mid = sessions.get(sessionId);
    if (mid == null)
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No session");

    return memberRepo.findById(mid)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No member"));
  }

  private void requireAdmin(Member me) {
    if (me.getRole() != ROLE_ADMIN)
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin only");
  }

  private void requireSameGroup(Member me, Long groupId) {
    if (me.getFamilyGroup() == null || !me.getFamilyGroup().getId().equals(groupId))
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Forbidden");
  }

  private byte[] decodeBase64(String b64) {
    if (b64 == null || b64.isBlank()) {
      return new byte[0];
    }
    try {
      return Base64.getDecoder().decode(b64);
    } catch (IllegalArgumentException ex) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Bad embeddingBase64", ex);
    }
  }

  private float[] bytesToFloatArray(byte[] bytes) {
    if (bytes == null || bytes.length == 0) {
      return new float[0];
    }
    
    // Usamos ByteBuffer para manejar la conversión y el orden de bytes
    FloatBuffer buf = ByteBuffer.wrap(bytes)
        .order(ByteOrder.LITTLE_ENDIAN)  // <--- ¡AQUÍ ESTÁ LA SOLUCIÓN!
        .asFloatBuffer();
    
    float[] out = new float[buf.remaining()];
    buf.get(out);
    return out;
}

  private double cosine(float[] a, float[] b) {
    if (a.length == 0 || b.length == 0 || a.length != b.length)
      return -1.0;

    double dot = 0;
    double na = 0;
    double nb = 0;

    for (int i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      na += a[i] * a[i];
      nb += b[i] * b[i];
    }
    if (na == 0 || nb == 0)
      return -1.0;
    return dot / (Math.sqrt(na) * Math.sqrt(nb));
  }

  private GroupResponse toGroupResponse(FamilyGroup g) {
    if (g == null)
      return null;
    return new GroupResponse(g.getId(), g.getName());
  }

  private MemberResponse toMemberResponse(Member m) {
    boolean hasEmb = m.getEmbedding() != null && m.getEmbedding().length > 0;
    Long gId = (m.getFamilyGroup() != null) ? m.getFamilyGroup().getId() : null;
    return new MemberResponse(
        m.getId(),
        gId,
        m.getName(),
        m.getEmail(),
        m.getContext(),
        m.getRole(),
        hasEmb);
  }

  // -------------------------
  // AUTH
  // -------------------------
  @PostMapping(value = "/auth/register", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<MemberResponse> register(@RequestBody RegisterRequest body) {
    if (body.name() == null || body.name().isBlank()
        || body.email() == null || body.email().isBlank()
        || body.password() == null || body.password().isBlank())
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Name, email and password required");

    if (memberRepo.findByEmail(body.email()).isPresent())
      throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");

    Member m = new Member();
    m.setName(body.name());
    m.setEmail(body.email());
    m.setContext(body.context());
    m.setRole(body.role());

    m.setPasswordHash(passwordEncoder.encode(body.password()));
    m.setEmbedding(null);

    return ResponseEntity.status(HttpStatus.CREATED).body(toMemberResponse(memberRepo.save(m)));
  }

  @PostMapping(value = "/auth/login", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<SessionResponse> login(@RequestBody LoginRequest body) {
    logger.info(">>> Login attempt for: {}", body.email());
    if (body.email() == null || body.email().isBlank()
        || body.password() == null || body.password().isBlank()) {
      logger.warn(">>> Login failed: Missing credentials");
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email and password required");
    }

    Member m = memberRepo.findByEmail(body.email())
        .orElseThrow(() -> {
          logger.warn(">>> Login failed: Email not found - {}", body.email());
          return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "The email address is not registered");
        });

    if (m.getPasswordHash() == null || !passwordEncoder.matches(body.password(), m.getPasswordHash())) {
      logger.warn(">>> Login failed: Incorrect password for {}", body.email());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Incorrect password");
    }

    String token = UUID.randomUUID().toString();
    sessions.put(token, m.getId());

    Long gId = (m.getFamilyGroup() != null) ? m.getFamilyGroup().getId() : null;
    logger.info(">>> Login successful for: {}", body.email());
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(new SessionResponse(token, m.getId(), gId, m.getRole()));
  }

  @DeleteMapping("/auth/logout/{sessionId}")
  public ResponseEntity<Void> logout(@PathVariable String sessionId) {
    sessions.remove(sessionId);
    return ResponseEntity.ok().build();
  }

  // -------------------------
  // GROUP / MEMBERS
  // -------------------------
  @GetMapping(value = "/group/me", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<GroupResponse> myGroup(@RequestHeader("X-Session-Id") String sessionId) {
    Member me = requireMemberFromSession(sessionId);
    return ResponseEntity.ok(toGroupResponse(me.getFamilyGroup()));
  }

  @GetMapping(value = "/group/{id}/member", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<List<MemberResponse>> getMembers(@RequestHeader("X-Session-Id") String sessionId,
      @PathVariable Long id) {
    Member me = requireMemberFromSession(sessionId);
    requireSameGroup(me, id);

    return ResponseEntity.ok(
        memberRepo.findByFamilyGroupId(id).stream().map(this::toMemberResponse).toList());
  }

  @PostMapping(value = "/group/memory", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<MemberResponse> createMemory(@RequestHeader("X-Session-Id") String sessionId,
      @RequestBody CreateMemoryRequest body) {
    Member me = requireMemberFromSession(sessionId);
    FamilyGroup g = me.getFamilyGroup();
    if (g == null)
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not in a group");

    if (body.name() == null || body.name().isBlank())
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Name required");

    byte[] emb = decodeBase64(body.embeddingBase64());
    if (emb.length == 0)
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "embeddingBase64 required");

    Member m = new Member();
    m.setName(body.name());
    m.setContext(body.context());
    m.setFamilyGroup(g);
    m.setRole(ROLE_MEMBER); // Passive member
    m.setEmbedding(emb);
    // No email/password for memories

    return ResponseEntity.status(HttpStatus.CREATED).body(toMemberResponse(memberRepo.save(m)));
  }

  @PostMapping(value = "/group/create", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<GroupResponse> createGroup(@RequestHeader("X-Session-Id") String sessionId,
      @RequestBody CreateGroupRequest body) {
    Member me = requireMemberFromSession(sessionId);
    requireAdmin(me);

    FamilyGroup g = new FamilyGroup();
    g.setName(body.name());
    g = groupRepo.save(g);

    me.setFamilyGroup(g);
    memberRepo.save(me);

    return ResponseEntity.status(HttpStatus.CREATED).body(toGroupResponse(g));
  }

  @PostMapping(value = "/group/join", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<MemberResponse> joinGroup(@RequestHeader("X-Session-Id") String sessionId,
      @RequestBody JoinGroupRequest body) {
    Member me = requireMemberFromSession(sessionId);
    logger.info(">>> Join attempt by user {} with code '{}'", me.getEmail(), body.inviteCode());

    if (body.inviteCode() == null || body.inviteCode().isBlank()) {
      logger.warn(">>> Join failed: inviteCode required");
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "inviteCode required");
    }

    FamilyGroup g = groupRepo.findByInviteCode(body.inviteCode())
        .orElseThrow(() -> {
          logger.warn(">>> Join failed: Code '{}' not found in DB", body.inviteCode());
          return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid inviteCode");
        });

    me.setFamilyGroup(g);
    logger.info(">>> Join successful: User {} joined group {}", me.getEmail(), g.getId());
    return ResponseEntity.ok(toMemberResponse(memberRepo.save(me)));
  }

  // -------------------------
  // INVITES (solo admin)
  // -------------------------
  @PostMapping(value = "/group/{id}/invite", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<InviteResponse> createInvite(@RequestHeader("X-Session-Id") String sessionId,
      @PathVariable Long id) {
    Member me = requireMemberFromSession(sessionId);
    requireAdmin(me);
    requireSameGroup(me, id);

    FamilyGroup g = me.getFamilyGroup();
    // Generate new code or return existing?
    // Let's generate a new one if it doesn't exist, or just return existing to be
    // idempotent?
    // User asked to SAVE it, usually implies generating one if one is not there.
    // Ideally duplicate calls should return the same code if valid, or a new one if
    // requested.
    // For simplicity: check if one exists, if so return it. If not, generate.
    String code = g.getInviteCode();
    if (code == null || code.isBlank()) {
      code = UUID.randomUUID().toString().substring(0, 8).toUpperCase();
      g.setInviteCode(code);
      groupRepo.save(g);
    }
    // Note: If we want to rotate codes, we might need a separate endpoint or param.
    // For now, persistent code per group seems safer.

    return ResponseEntity.status(HttpStatus.CREATED).body(new InviteResponse(code, id));
  }

  // -------------------------
  // EMBEDDING
  // -------------------------
  @PutMapping(value = "/member/{id}/embedding", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<MemberResponse> setEmbedding(@RequestHeader("X-Session-Id") String sessionId,
      @PathVariable Long id,
      @RequestBody SetEmbeddingRequest body) {
    Member me = requireMemberFromSession(sessionId);

    Member target = memberRepo.findById(id)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No member"));

    requireSameGroup(me, target.getFamilyGroup().getId());
    if (!me.getId().equals(id))
      requireAdmin(me);

    byte[] emb = decodeBase64(body.embeddingBase64());
    if (emb.length == 0)
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "embeddingBase64 required");

    target.setEmbedding(emb);
    return ResponseEntity.ok(toMemberResponse(memberRepo.save(target)));
  }

  // -------------------------
  // RECOGNIZE
  // -------------------------
  @PostMapping(value = "/group/{id}/recognize", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<List<RecognizeRow>> recognize(@RequestHeader("X-Session-Id") String sessionId,
      @PathVariable Long id,
      @RequestBody RecognizeRequest body) {
    Member me = requireMemberFromSession(sessionId);
    requireSameGroup(me, id);

    byte[] queryBytes = decodeBase64(body.embeddingBase64());
    if (queryBytes.length == 0)
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "embeddingBase64 required");

    float[] q = bytesToFloatArray(queryBytes);

    double minSim = body.minSim();
    int safeTop = Math.max(1, Math.min(body.top(), 50));

    List<RecognizeRow> ranked = memberRepo.findByFamilyGroupId(id).stream()
        .filter(m -> m.getEmbedding() != null && m.getEmbedding().length > 0)
        .map(m -> new AbstractMap.SimpleEntry<>(m, cosine(q, bytesToFloatArray(m.getEmbedding()))))
        .filter(e -> e.getValue() >= minSim)
        .sorted((a, b) -> Double.compare(b.getValue(), a.getValue()))
        .limit(safeTop)
        .map(e -> new RecognizeRow(
            e.getKey().getId(),
            e.getKey().getName(),
            e.getKey().getEmail(),
            e.getKey().getContext(),
            e.getValue()))
        .toList();

    return ResponseEntity.ok(ranked);
  }
}
