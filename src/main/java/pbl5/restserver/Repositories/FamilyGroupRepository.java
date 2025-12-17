package pbl5.restserver.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import pbl5.restserver.model.FamilyGroup;

import java.util.List;

public interface FamilyGroupRepository extends JpaRepository<FamilyGroup, Long> {
    
}
