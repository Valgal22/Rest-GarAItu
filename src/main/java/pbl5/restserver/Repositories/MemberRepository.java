package pbl5.restserver.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import pbl5.restserver.model.Member;

import java.util.List;

public interface MemberRepository extends JpaRepository<Member, Long> {
    List<Member> findByFamilyGroupId(Long familyGroupId);
    List<Member> findByName(String name);
}
