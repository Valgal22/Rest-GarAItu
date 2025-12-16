package pbl5.restserver.model;

import jakarta.persistence.*;

@Entity
@Table(name = "family_group")
public class FamilyGroup {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "caregiver_id", nullable = false)
    private Caregiver caregiver;

    @Column(nullable = false, length = 100)
    private String name;

    public FamilyGroup() {}

    public FamilyGroup(Long id, Caregiver caregiver, String name) {
        this.id = id;
        this.caregiver = caregiver;
        this.name = name;
    }

    public FamilyGroup(Caregiver caregiver, String name) {
        this.caregiver = caregiver;
        this.name = name;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Caregiver getCaregiver() { return caregiver; }
    public void setCaregiver(Caregiver caregiver) { this.caregiver = caregiver; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}
