package pbl5.restserver.model;

import jakarta.persistence.*;

@Entity
@Table(name = "member")
public class Member {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(optional = false, fetch = FetchType.LAZY)
  @JoinColumn(name = "family_group_id", nullable = false)
  private FamilyGroup familyGroup;

  @Column(nullable = false, length = 100)
  private String name;

  @Column(length = 100)
  private String context;

  @Column(nullable = false)
  private short role;

  @Column(name = "password_hash", length = 100)
  private String passwordHash;

  @Column(length = 50)
  private String email;

  @Lob
  @Basic(fetch = FetchType.LAZY)
  @Column(name = "embedding", columnDefinition = "LONGBLOB")
  private byte[] embedding;

  public Member() {}

  public Long getId() { return id; }
  public void setId(Long id) { this.id = id; }

  public FamilyGroup getFamilyGroup() { return familyGroup; }
  public void setFamilyGroup(FamilyGroup familyGroup) { this.familyGroup = familyGroup; }

  public String getName() { return name; }
  public void setName(String name) { this.name = name; }

  public String getContext() { return context; }
  public void setContext(String context) { this.context = context; }

  public short getRole() { return role; }
  public void setRole(short role) { this.role = role; }

  public String getPasswordHash() { return passwordHash; }
  public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

  public String getEmail() { return email; }
  public void setEmail(String email) { this.email = email; }

  public byte[] getEmbedding() { return embedding; }
  public void setEmbedding(byte[] embedding) { this.embedding = embedding; }
}
