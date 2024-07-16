package com.vibramium.authn.repository;

import com.vibramium.authn.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token,Long> {

    @Query(
            "SELECT t " +
                    "FROM Token t " +
                    "JOIN t.user u " +
                    "WHERE u.id = :userId " +
                    "AND (t.expired = false OR t.revoked = false)"
    )
    List<Token> findActiveTokensByUserId(Long userId);

    Optional<Token> findByToken(String token);

}
