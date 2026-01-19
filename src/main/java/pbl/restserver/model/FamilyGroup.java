package pbl.restserver.model;

import jakarta.persistence.*;

@Entity
@Table(name = "family_group")
public class FamilyGroup {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(unique = true)
  private String inviteCode;

  public String getInviteCode() {
    return inviteCode;
  }

  public void setInviteCode(String inviteCode) {
    this.inviteCode = inviteCode;
  }

  @Column(nullable = false, length = 100, unique = true)
  private String name;

  public FamilyGroup() {
  }

  public FamilyGroup(String name) {
    this.name = name;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }
}
