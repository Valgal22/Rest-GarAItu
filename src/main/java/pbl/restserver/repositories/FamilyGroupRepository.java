package pbl.restserver.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import pbl.restserver.model.FamilyGroup;

public interface FamilyGroupRepository extends JpaRepository<FamilyGroup, Long> {
    Optional<FamilyGroup> findByInviteCode(String inviteCode);

    Optional<FamilyGroup> findByName(String name);

}
