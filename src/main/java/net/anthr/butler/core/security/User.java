package net.anthr.butler.core.security;

import jakarta.persistence.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.UUID;

@Entity
@Table(name = "users")
public class User {

    @Transient
    private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String passwordHash;

    @Column(unique = true)
    private Long telegramId;

    protected User() {} // required by JPA

    public User(String username, String rawPassword) {
        this.username = username;
        this.passwordHash = ENCODER.encode(rawPassword);
    }

    public UUID id() { return id; }

    public String username() { return username; }

    public String passwordHash() { return passwordHash; }

    public boolean checkPassword(String rawPassword) {
        return ENCODER.matches(rawPassword, passwordHash);
    }

    public Long telegramId() { return telegramId; }

    public void setTelegramId(Long telegramId) { this.telegramId = telegramId; }

}