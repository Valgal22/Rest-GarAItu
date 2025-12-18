package pbl5.restserver.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import pbl5.restserver.model.FamilyGroup;

public interface FamilyGroupRepository extends JpaRepository<FamilyGroup, Long> {
    
}
