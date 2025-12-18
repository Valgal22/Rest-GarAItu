package pbl.restserver.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import pbl.restserver.model.FamilyGroup;

public interface FamilyGroupRepository extends JpaRepository<FamilyGroup, Long> {
    
}
