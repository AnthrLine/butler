package net.anthr.butler.core.security;

import jakarta.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String passwordHash;

    @Column(unique = true)
    private Long telegramId;

    public User(String username, String password) {}

    public UUID id() { return id; }

    public String username() { return username; }

    public String passwordHash() { return passwordHash; }

    public Long telegramId() { return telegramId; }

    public void setTelegramId(Long telegramId) { this.telegramId = telegramId; }

}