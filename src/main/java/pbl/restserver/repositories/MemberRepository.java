package pbl.restserver.repositories;


import org.springframework.data.jpa.repository.JpaRepository;

import pbl.restserver.model.Member;

import java.util.Optional;
import java.util.List;

public interface MemberRepository extends JpaRepository<Member, Long> {
  List<Member> findByFamilyGroupId(Long familyGroupId);
  Optional<Member> findByEmail(String email);
}
