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
    private String relation;

    @Lob
    private String description;

    @Lob
    @Column(name = "embedding")
    private byte[] embedding;

    @Column(name = "model_version", length = 50)
    private String modelVersion = "uniface-v1";

    public Member() {}

    public Member(FamilyGroup familyGroup, String name, String relation, String description, byte[] embedding, String modelVersion) {
        this.familyGroup = familyGroup;
        this.name = name;
        this.relation = relation;
        this.description = description;
        this.embedding = embedding;
        this.modelVersion = modelVersion;
    }

    // getters/setters (incluye embedding y modelVersion)
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public FamilyGroup getFamilyGroup() { return familyGroup; }
    public void setFamilyGroup(FamilyGroup familyGroup) { this.familyGroup = familyGroup; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getRelation() { return relation; }
    public void setRelation(String relation) { this.relation = relation; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public byte[] getEmbedding() { return embedding; }
    public void setEmbedding(byte[] embedding) { this.embedding = embedding; }

    public String getModelVersion() { return modelVersion; }
    public void setModelVersion(String modelVersion) { this.modelVersion = modelVersion; }
}
