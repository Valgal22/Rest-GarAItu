package pbl5.restserver.controller;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import pbl5.restserver.Repositories.CaregiverRepository;
import pbl5.restserver.Repositories.FamilyGroupRepository;
import pbl5.restserver.Repositories.MemberRepository;
import pbl5.restserver.model.*;

@CrossOrigin(maxAge = 3600)
@RestController
@RequestMapping("/garAItu")
public class Controller {

  private final CaregiverRepository caregiverRepo;
  private final FamilyGroupRepository groupRepo;
  private final MemberRepository memberRepo;
  private final PasswordEncoder passwordEncoder;

  // token -> caregiverId
  private final Map<String, Long> sessions = new ConcurrentHashMap<>();

  public Controller(CaregiverRepository caregiverRepo,
                    FamilyGroupRepository groupRepo,
                    MemberRepository memberRepo,
                    PasswordEncoder passwordEncoder) {
    this.caregiverRepo = caregiverRepo;
    this.groupRepo = groupRepo;
    this.memberRepo = memberRepo;
    this.passwordEncoder = passwordEncoder;
  }

  // -------------------------
  // DTOs
  // -------------------------
  public static record LoginRequest(String email, String password) {}
  public static record SessionResponse(String session, Long id) {}

  public static record CaregiverCreateRequest(String name, String email, String password) {}
  public static record CaregiverResponse(Long id, String name, String email) {}

  public static record GroupRequest(String name) {}
  public static record GroupResponse(Long id, String name) {}

  public static record MemberResponse(Long id, String name, String relation, String description, String modelVersion) {}
  public static record SimilarMemberRow(Long id, String name, String relation, String description, double similarity) {}

  public static class MemberRequest {
    public String name;
    public String relation;
    public String description;
    public String embeddingBase64;
    public String modelVersion;
  }

  // -------------------------
  // Helpers
  // -------------------------
  private Long requireCaregiverFromSession(String sessionId) {
    if (sessionId == null || sessionId.isBlank())
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No session");
    Long cid = sessions.get(sessionId);
    if (cid == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No session");
    return cid;
  }

  private void requireOwnership(FamilyGroup g, Long caregiverId) {
    if (!g.getCaregiver().getId().equals(caregiverId))
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Forbidden");
  }

  private void requireOwnership(Member m, Long caregiverId) {
    if (!m.getFamilyGroup().getCaregiver().getId().equals(caregiverId))
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Forbidden");
  }

  private byte[] decodeBase64(String b64) {
    if (b64 == null || b64.isBlank()) return null;
    try {
      return Base64.getDecoder().decode(b64);
    } catch (IllegalArgumentException ex) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Bad embeddingBase64");
    }
  }

  private float[] bytesToFloatArray(byte[] bytes) {
    if (bytes == null || bytes.length == 0) return null;
    if (bytes.length % 4 != 0)
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Bad embedding bytes length");
    int n = bytes.length / 4;
    float[] out = new float[n];
    for (int i = 0; i < n; i++) {
      int base = i * 4;
      int bits = ((bytes[base] & 0xFF) << 24)
               | ((bytes[base + 1] & 0xFF) << 16)
               | ((bytes[base + 2] & 0xFF) << 8)
               |  (bytes[base + 3] & 0xFF);
      out[i] = Float.intBitsToFloat(bits);
    }
    return out;
  }

  private double cosine(float[] a, float[] b) {
    if (a == null || b == null || a.length != b.length) return -1.0;
    double dot = 0, na = 0, nb = 0;
    for (int i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      na += a[i] * a[i];
      nb += b[i] * b[i];
    }
    if (na == 0 || nb == 0) return -1.0;
    return dot / (Math.sqrt(na) * Math.sqrt(nb));
  }

  private GroupResponse toGroupResponse(FamilyGroup g) {
    return new GroupResponse(g.getId(), g.getName());
  }

  private MemberResponse toMemberResponse(Member m) {
    return new MemberResponse(m.getId(), m.getName(), m.getRelation(), m.getDescription(), m.getModelVersion());
  }

  // -------------------------
  // CAREGIVERS (registro)
  // -------------------------
  @PostMapping(value="/caregivers", consumes=MediaType.APPLICATION_JSON_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<CaregiverResponse> createCaregiver(@RequestBody CaregiverCreateRequest body) {
    if (body.email() == null || body.email().isBlank() || body.password() == null || body.password().isBlank())
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email and password required");

    if (caregiverRepo.findByEmail(body.email()).isPresent())
      throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");

    Caregiver cg = new Caregiver();
    cg.setName(body.name());
    cg.setEmail(body.email());
    cg.setPasswordHash(passwordEncoder.encode(body.password())); // BCrypt aquí

    Caregiver saved = caregiverRepo.save(cg);
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(new CaregiverResponse(saved.getId(), saved.getName(), saved.getEmail()));
  }

  // -------------------------
  // SESSIONS
  // -------------------------
  @PostMapping(value="/sessions", consumes=MediaType.APPLICATION_JSON_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<SessionResponse> login(@RequestBody LoginRequest body) {
    if (body.email() == null || body.password() == null)
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email and password required");

    Caregiver cg = caregiverRepo.findByEmail(body.email())
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bad credentials"));

    if (!passwordEncoder.matches(body.password(), cg.getPasswordHash()))
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bad credentials");

    String token = UUID.randomUUID().toString();
    sessions.put(token, cg.getId());
    return ResponseEntity.status(HttpStatus.CREATED).body(new SessionResponse(token, cg.getId()));
  }

  @DeleteMapping("/sessions/{id}")
  public ResponseEntity<Void> logout(@PathVariable String id) {
    sessions.remove(id);
    return ResponseEntity.ok().build();
  }

  // -------------------------
  // GROUPS
  // -------------------------
  @GetMapping(value="/group", produces=MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<List<GroupResponse>> getGroups(@RequestHeader("X-Session-Id") String sessionId) {
    Long caregiverId = requireCaregiverFromSession(sessionId);
    return ResponseEntity.ok(groupRepo.findByCaregiverId(caregiverId).stream().map(this::toGroupResponse).toList());
  }

  @PostMapping(value="/group", consumes=MediaType.APPLICATION_JSON_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<GroupResponse> createGroup(@RequestHeader("X-Session-Id") String sessionId,
                                                  @RequestBody GroupRequest body) {
    Long caregiverId = requireCaregiverFromSession(sessionId);
    if (body.name() == null || body.name().isBlank())
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Name required");

    Caregiver cg = caregiverRepo.findById(caregiverId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No caregiver"));

    FamilyGroup g = new FamilyGroup();
    g.setCaregiver(cg);
    g.setName(body.name());

    return ResponseEntity.status(HttpStatus.CREATED).body(toGroupResponse(groupRepo.save(g)));
  }

  @PutMapping(value="/group/{id}", consumes=MediaType.APPLICATION_JSON_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<GroupResponse> updateGroup(@RequestHeader("X-Session-Id") String sessionId,
                                                  @PathVariable Long id,
                                                  @RequestBody GroupRequest body) {
    Long caregiverId = requireCaregiverFromSession(sessionId);
    if (body.name() == null || body.name().isBlank())
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Name required");

    FamilyGroup g = groupRepo.findById(id)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No group"));

    requireOwnership(g, caregiverId);

    g.setName(body.name());
    return ResponseEntity.ok(toGroupResponse(groupRepo.save(g)));
  }

  @DeleteMapping("/group/{id}")
  public ResponseEntity<Void> deleteGroup(@RequestHeader("X-Session-Id") String sessionId, @PathVariable Long id) {
    Long caregiverId = requireCaregiverFromSession(sessionId);

    FamilyGroup g = groupRepo.findById(id)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No group"));

    requireOwnership(g, caregiverId);

    groupRepo.delete(g);
    return ResponseEntity.ok().build();
  }

  // -------------------------
  // MEMBERS
  // -------------------------
  @GetMapping(value="/group/{id}/member", produces=MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<?> getMembers(@RequestHeader("X-Session-Id") String sessionId,
                                      @PathVariable Long id,
                                      @RequestParam(required=false) Long similarToMemberId,
                                      @RequestParam(required=false, defaultValue="0.0") double minSim,
                                      @RequestParam(required=false, defaultValue="5") int top) {
    Long caregiverId = requireCaregiverFromSession(sessionId);

    FamilyGroup g = groupRepo.findById(id)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No group"));
    requireOwnership(g, caregiverId);

    List<Member> members = memberRepo.findByFamilyGroupId(id);

    if (similarToMemberId == null) {
      return ResponseEntity.ok(members.stream().map(this::toMemberResponse).toList());
    }

    Member ref = memberRepo.findById(similarToMemberId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No member ref"));
    requireOwnership(ref, caregiverId);

    float[] refVec = bytesToFloatArray(ref.getEmbedding());
    int safeTop = Math.max(1, Math.min(top, 50));

    List<SimilarMemberRow> ranked = members.stream()
        .filter(m -> !m.getId().equals(similarToMemberId))
        .filter(m -> m.getEmbedding() != null && m.getEmbedding().length > 0)
        .map(m -> new AbstractMap.SimpleEntry<>(m, cosine(refVec, bytesToFloatArray(m.getEmbedding()))))
        .filter(e -> e.getValue() >= minSim)
        .sorted((a, b) -> Double.compare(b.getValue(), a.getValue()))
        .limit(safeTop)
        .map(e -> new SimilarMemberRow(
            e.getKey().getId(),
            e.getKey().getName(),
            e.getKey().getRelation(),
            e.getKey().getDescription(),
            e.getValue()
        ))
        .collect(Collectors.toList());

    return ResponseEntity.ok(ranked);
  }

  @PostMapping(value="/group/{id}/member", consumes=MediaType.APPLICATION_JSON_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<MemberResponse> createMember(@RequestHeader("X-Session-Id") String sessionId,
                                                    @PathVariable Long id,
                                                    @RequestBody MemberRequest body) {
    Long caregiverId = requireCaregiverFromSession(sessionId);

    FamilyGroup g = groupRepo.findById(id)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No group"));
    requireOwnership(g, caregiverId);

    if (body.name == null || body.name.isBlank())
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Name required");

    Member m = new Member();
    m.setFamilyGroup(g);
    m.setName(body.name);
    m.setRelation(body.relation);
    m.setDescription(body.description);
    m.setEmbedding(decodeBase64(body.embeddingBase64));
    m.setModelVersion(body.modelVersion);

    return ResponseEntity.status(HttpStatus.CREATED).body(toMemberResponse(memberRepo.save(m)));
  }

  @PutMapping(value="/member/{id}", consumes=MediaType.APPLICATION_JSON_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<MemberResponse> updateMember(@RequestHeader("X-Session-Id") String sessionId,
                                                    @PathVariable Long id,
                                                    @RequestBody MemberRequest body) {
    Long caregiverId = requireCaregiverFromSession(sessionId);

    Member m = memberRepo.findById(id)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No member"));
    requireOwnership(m, caregiverId);

    if (body.name != null) m.setName(body.name);
    if (body.relation != null) m.setRelation(body.relation);
    if (body.description != null) m.setDescription(body.description);
    if (body.embeddingBase64 != null) m.setEmbedding(decodeBase64(body.embeddingBase64));
    if (body.modelVersion != null) m.setModelVersion(body.modelVersion);

    return ResponseEntity.ok(toMemberResponse(memberRepo.save(m)));
  }

  @DeleteMapping("/member/{id}")
  public ResponseEntity<Void> deleteMember(@RequestHeader("X-Session-Id") String sessionId, @PathVariable Long id) {
    Long caregiverId = requireCaregiverFromSession(sessionId);

    Member m = memberRepo.findById(id)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No member"));
    requireOwnership(m, caregiverId);

    memberRepo.delete(m);
    return ResponseEntity.ok().build();
  }
}
