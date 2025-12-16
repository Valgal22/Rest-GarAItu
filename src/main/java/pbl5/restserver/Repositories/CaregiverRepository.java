package pbl5.restserver.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import pbl5.restserver.model.Caregiver;

import java.util.Optional;

public interface CaregiverRepository extends JpaRepository<Caregiver, Long> {
    Optional<Caregiver> findByEmail(String email);
}
