package pbl5.restserver.Repositories;


import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.List;
import pbl5.restserver.model.Member;

public interface MemberRepository extends JpaRepository<Member, Long> {
  List<Member> findByFamilyGroupId(Long familyGroupId);
  Optional<Member> findByEmail(String email);
}
