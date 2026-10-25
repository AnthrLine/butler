package net.anthr.butler.core.security;

import jakarta.persistence.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User {

    @Transient
    private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();

    @Transient
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Length in bytes of the random key id (public, used to look up the row). */
    @Transient
    private static final int KEY_ID_BYTES = 9;   // 12 chars base64url

    /** Length in bytes of the random secret (the part that gets hashed). */
    @Transient
    private static final int KEY_SECRET_BYTES = 32; // 43 chars base64url

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String passwordHash;

    /** Public, indexable identifier for the API key. */
    @Column(unique = true)
    private String apiKeyId;

    /** BCrypt hash of the secret part of the API key. */
    @Column
    private String apiKeyHash;

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

    public String apiKeyId() { return apiKeyId; }

    /**
     * Generates a new API key for this user, stores only the hashed secret,
     * and returns the raw key exactly once. The caller MUST surface it to the
     * end user immediately; it cannot be recovered later.
     *
     * Will overwrite any previous keys.
     *
     * Format: {@code ak_<keyId>.<secret>} (both parts base64url without padding).
     */
    public String generateApiKey() {
        String keyId = randomBase64Url(KEY_ID_BYTES);
        String secret = randomBase64Url(KEY_SECRET_BYTES);

        this.apiKeyId = keyId;
        this.apiKeyHash = ENCODER.encode(secret);

        return "ak_" + keyId + "." + secret;
    }

    /** Clears the current API key. */
    public void revokeApiKey() {
        this.apiKeyId = null;
        this.apiKeyHash = null;
    }

    /** Verifies the given secret against the stored BCrypt hash. */
    public boolean checkApiKeySecret(String rawSecret) {
        return apiKeyHash != null && ENCODER.matches(rawSecret, apiKeyHash);
    }

    private static String randomBase64Url(int numBytes) {
        byte[] bytes = new byte[numBytes];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
