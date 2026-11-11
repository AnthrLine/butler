package net.anthr.butler.core.security;

public record UserRegistrationDto(
        String username,
        String password
) {}
