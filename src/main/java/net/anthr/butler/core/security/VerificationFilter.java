package net.anthr.butler.core.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.util.Base64;
import java.util.Optional;

@Component
public class VerificationFilter implements Filter {

    private static final String API_KEY_PREFIX = "ak_";

    private final UserRepository userRepository;

    public VerificationFilter(UserRepository usuariRepository) {
        this.userRepository = usuariRepository;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException { // TODO #tidyup refactor to be more readable.

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // IGNORE PUBLIC PATHS
        String path = httpRequest.getRequestURI();

        if (path.startsWith("/api/security/user/register")) {
            chain.doFilter(request, response);
            return;
        }

        // 1. API KEY CHECK
        String apiKeyHeader = httpRequest.getHeader("X-API-Key");
        if (apiKeyHeader != null) {
            if (isValidApiKey(apiKeyHeader)) {
                chain.doFilter(request, response);
                return;
            }
            httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpResponse.getWriter().write("Invalid API key");
            return;
        }

        // 2. STANDARD CHECK
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            // Extract user:password
            String base64Credentials = authHeader.substring("Basic ".length()).trim();
            byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
            String credentials = new String(credDecoded);
            String[] values = credentials.split(":", 2);

            if (values.length == 2) {
                String username = values[0];
                String password = values[1];

                Optional<User> user = userRepository.findByUsername(username);

                if (user.isPresent() && user.get().checkPassword(password)) {
                    chain.doFilter(request, response);
                    return;
                }
            }
        }

        // Non verified requests
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpResponse.getWriter().write("Non authorised");
    }

    /**
     * Parses a raw API key of the form {@code ak_<keyId>.<secret>}, looks up
     * the user by {@code keyId}, and BCrypt-verifies the secret.
     */
    private boolean isValidApiKey(String rawKey) {
        if (!rawKey.startsWith(API_KEY_PREFIX)) return false;

        String body = rawKey.substring(API_KEY_PREFIX.length());
        int dot = body.indexOf('.');
        if (dot <= 0 || dot == body.length() - 1) return false;

        String keyId = body.substring(0, dot);
        String secret = body.substring(dot + 1);

        return userRepository.findByApiKeyId(keyId)
                .map(user -> user.checkApiKeySecret(secret))
                .orElse(false);
    }
}
