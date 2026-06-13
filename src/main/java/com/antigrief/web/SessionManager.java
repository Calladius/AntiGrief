package com.antigrief.web;

import com.antigrief.config.ConfigManager;
import com.antigrief.database.repository.WebAccountRepository;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;

// токены сессий, создание/валидация в бд
public class SessionManager {

    private final ConfigManager configManager;
    private final WebAccountRepository webAccountRepository;
    private final SecureRandom random = new SecureRandom();

    public SessionManager(ConfigManager configManager, WebAccountRepository webAccountRepository) {
        this.configManager = configManager;
        this.webAccountRepository = webAccountRepository;
    }

    // 32 байта → hex (64 символа)
    public String generateToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    public String createSession(int accountId, String ip) {
        String token = generateToken();
        int maxAge = configManager.getSessionMaxAge();
        String expiresAt = LocalDateTime.now()
            .plusSeconds(maxAge)
            .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
            .replace("T", " ");

        if (webAccountRepository.createSession(accountId, token, ip, expiresAt)) {
            webAccountRepository.updateLastLogin(accountId);
            return token;
        }
        return null;
    }

    public int validateSession(String token) {
        return webAccountRepository.validateSession(token);
    }

    public boolean deleteSession(String token) {
        return webAccountRepository.deleteSession(token);
    }

    public boolean deleteAllSessions(int accountId) {
        return webAccountRepository.deleteSessionsByAccount(accountId);
    }

    public WebAccountRepository.AccountData getAccountFromToken(String token) {
        int accountId = validateSession(token);
        if (accountId <= 0) return null;
        return webAccountRepository.getAccount(accountId);
    }

    public int getSessionMaxAge() {
        return configManager.getSessionMaxAge();
    }
}
