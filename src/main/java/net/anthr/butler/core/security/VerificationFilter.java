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

    private final UserRepository userRepository;

    public VerificationFilter(UserRepository usuariRepository) {
        this.userRepository = usuariRepository;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException { // TODO #tidyup refactor to be more readable.

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String path = httpRequest.getRequestURI();

        // 1. TELEGRAM CHECK
        String telegramIdHeader = httpRequest.getHeader("X-Telegram-Id");
        if (telegramIdHeader != null) {
            try {
                Long telegramId = Long.parseLong(telegramIdHeader);
                Optional<User> usuariTelegram = userRepository.findByTelegramId(telegramId);

                if (usuariTelegram.isPresent()) {
                    // Usuari de Telegram trobat i vàlid! Deixem passar la sol·licitud.
                    chain.doFilter(request, response);
                    return;
                }
            } catch (NumberFormatException e) {
                httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                httpResponse.getWriter().write("Telegram Id is not a number");
                return;
            }
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
}