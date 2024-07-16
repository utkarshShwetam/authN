package com.vibramium.authn.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.vibramium.authn.type.TokenType;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "token",
    uniqueConstraints = {
            @UniqueConstraint(columnNames = "token",
                    name = "token_token_unique"
            )
    }
)
@EntityListeners(AuditingEntityListener.class)
public class Token {

    @Id
    @SequenceGenerator(name = "token_id_sequence", allocationSize = 1)
    @GeneratedValue(
            strategy = GenerationType.SEQUENCE,
            generator = "token_id_sequence"
    )
    private Long Id;

    @Column(name = "token",nullable = false,unique = true)
    private String token;

    @Enumerated(EnumType.STRING)
    @Column(name = "token_type",nullable = false)
    private TokenType tokenType;

    @Column(name = "expired",nullable = false)
    private Boolean expired;

    @Column(name = "revoked",nullable = false)
    private Boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id",nullable = false)
    private User user;

    @CreatedDate
    @Column(name = "created_at",nullable = false)
    @JsonIgnore
    private LocalDateTime createdDate;

    @LastModifiedDate
    @Column(name = "updated_at" ,nullable = false)
    @JsonIgnore
    private LocalDateTime lastModifiedDate;

}
