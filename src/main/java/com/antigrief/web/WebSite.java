package com.antigrief.web;

import com.antigrief.AntiGriefPlugin;
import com.antigrief.check.IpChecker;
import com.antigrief.check.VpnChecker;
import com.antigrief.database.repository.DeviceFingerprintRepository;
import com.antigrief.database.repository.FingerprintRepository;
import com.antigrief.database.repository.IpBanRepository;
import com.antigrief.database.repository.PlayerNickRepository;
import com.antigrief.database.repository.WebAccountRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.security.SecureRandom;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

// веб-сервер на javalin
// сессия: ?s=TOKEN > cookie ag_session, ставится только из JS (без HttpOnly)
// после oauth callback — рендерим профиль напрямую
public class WebSite {

    private final AntiGriefPlugin plugin;
    private Javalin app;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final IpChecker ipChecker;
    // fp.js с диска
    private String FP_JS = "";

    public WebSite(AntiGriefPlugin plugin) {
        this.plugin = plugin;
        
        // загружаем fp.js с диска
        try {
            java.nio.file.Path fpPath = java.nio.file.Paths.get(plugin.getDataFolder().getAbsolutePath(), "static", "fp.js");
            if (java.nio.file.Files.exists(fpPath)) {
                this.FP_JS = java.nio.file.Files.readString(fpPath);
                plugin.getLogger().info("FingerprintJS v5 IIFE загружен (" + FP_JS.length() + " байт)");
            } else {
                plugin.getLogger().warning("Файл static/fp.js не найден — будет использован fallback canvas+WebGL");
            }
        } catch (Exception e) {
            plugin.getLogger().warning("Не удалось загрузить fp.js: " + e.getMessage());
        }
        
        // http клиент с SOCKS5
        HttpClient.Builder clientBuilder = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10));
        
        // SOCKS5 если настроен
        String proxyHost = plugin.getConfigManager().getProxyHost();
        int proxyPort = plugin.getConfigManager().getProxyPort();
        if (proxyHost != null && !proxyHost.isEmpty() && proxyPort > 0) {
            clientBuilder.proxy(ProxySelector.of(new InetSocketAddress(proxyHost, proxyPort)));
            plugin.getLogger().info("HTTP клиент использует SOCKS5 прокси: " + proxyHost + ":" + proxyPort);
        }
        
        this.httpClient = clientBuilder.build();
        this.objectMapper = new ObjectMapper();
        this.ipChecker = plugin.getIpChecker();
    }

    public void start() {
        app = Javalin.create(config -> {
            config.showJavalinBanner = false;
        });

        // логин
        app.get("/login", this::handleLogin);

        // discord oauth2
        app.get("/auth/discord", this::handleDiscordRedirect);
        app.get("/auth/discord/callback", this::handleDiscordCallback);

        // google oauth2
        app.get("/auth/google", this::handleGoogleRedirect);
        app.get("/auth/google/callback", this::handleGoogleCallback);

        // vk oauth2
        app.get("/auth/vk", this::handleVkRedirect);
        app.get("/auth/vk/callback", this::handleVkCallback);

        // telegram oauth2
        app.get("/auth/telegram", this::handleTelegramRedirect);
        app.get("/auth/telegram/callback", this::handleTelegramCallback);

        // профиль
        app.get("/profile", this::handleProfile);

        // привязка/отвязка ников
        app.post("/link-minecraft", this::handleLinkMinecraft);
        app.post("/unlink-minecraft", this::handleUnlinkMinecraft);

        // выход
        app.get("/logout", this::handleLogout);

        // fingerprint (приём от js)
        app.post("/fingerprint", this::handleFingerprint);

        // проверка бана (localStorage)
        app.get("/check-ban", this::handleCheckBan);

        // статика
        app.get("/style.css", this::handleStyleCss);
        app.get("/fp.js", this::handleFpJs);

        app.start(plugin.getConfigManager().getWebsitePort());
    }

    public void stop() {
        if (app != null) {
            app.stop();
        }
    }

    // ==================== Утилиты сессий ====================

    // из ?s=, cookie ag_session или formParam
    private WebAccountRepository.AccountData getAccountFromSession(Context ctx) {
        String token = ctx.queryParam("s");
        if (token == null || token.isEmpty()) token = ctx.cookie("ag_session");
        if (token == null || token.isEmpty()) token = ctx.formParam("s");
        if (token == null || token.isEmpty()) return null;
        return plugin.getSessionManager().getAccountFromToken(token);
    }


    private String getTokenFromRequest(Context ctx) {
        String token = ctx.queryParam("s");
        if (token == null || token.isEmpty()) token = ctx.cookie("ag_session");
        if (token == null || token.isEmpty()) token = ctx.formParam("s");
        return token;
    }

    // ==================== Маршруты ====================


    private void handleLogin(Context ctx) {
        String nick = ctx.queryParam("nick");
        if (nick != null && !nick.isEmpty()) {
            ctx.cookie("ag_minecraft_nick", nick, plugin.getConfigManager().getNickCookieMaxAge());
        }

        WebAccountRepository.AccountData account = getAccountFromSession(ctx);
        if (account != null) {
            String token = getTokenFromRequest(ctx);
            ctx.redirect(token != null ? "/profile?s=" + token : "/profile");
            return;
        }

        ctx.contentType("text/html");
        ctx.result(renderLoginPage());
    }


    private void handleDiscordRedirect(Context ctx) {
        String clientId = plugin.getConfigManager().getDiscordClientId();
        String redirectUri = plugin.getConfigManager().getExternalUrl() + "/auth/discord/callback";
        String url = "https://discord.com/oauth2/authorize?client_id=" + clientId
            + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
            + "&response_type=code&scope=identify";
        ctx.redirect(url);
    }

    // рендерим профиль напрямую, без редиректа
    private void handleDiscordCallback(Context ctx) {
        String code = ctx.queryParam("code");
        if (code == null || code.isEmpty()) { ctx.contentType("text/html").result(renderError("Код авторизации не получен", "/login")); return; }

        try {
            // проверка vpn/гео до сессии
            String vpnError = checkVpnAndGeo(ctx);
            if (vpnError != null) { ctx.contentType("text/html"); ctx.result(vpnError); return; }

            // проверка забаненных IP
            String ipError = checkBannedIp(ipChecker.getIpFromWeb(ctx));
            if (ipError != null) { ctx.contentType("text/html"); ctx.result(ipError); return; }

            String accessToken = exchangeDiscordCode(code);
            if (accessToken == null) { ctx.contentType("text/html").result(renderError("Не удалось получить токен Discord", "/login")); return; }

            DiscordUserInfo user = getDiscordUserInfo(accessToken);
            if (user == null) { ctx.contentType("text/html").result(renderError("Не удалось получить информацию Discord", "/login")); return; }

            WebAccountRepository.AccountData account = findOrCreateAccount("discord", user.id, user.username);
            if (account == null) { ctx.contentType("text/html").result(renderError("Не удалось создать аккаунт", "/login")); return; }

            // проверка бана аккаунта
            String banError = checkAccountBan(account);
            if (banError != null) { ctx.contentType("text/html"); ctx.result(banError); return; }

            String ip = ipChecker.getIpFromWeb(ctx);
            String token = plugin.getSessionManager().createSession(account.id, ip);
            if (token == null) { ctx.contentType("text/html").result(renderError("Не удалось создать сессию", "/login")); return; }

            autoLinkNick(ctx, account);
            confirmNewIpLogin(ctx, account);
            ctx.contentType("text/html");
            ctx.result(renderProfileWithCookie(account, token));
        } catch (Exception e) {
            plugin.getLogger().severe("Ошибка Discord OAuth2: " + e.getMessage());
            ctx.contentType("text/html").result(renderError("Внутренняя ошибка сервера", "/login"));
        }
    }


    private void handleGoogleRedirect(Context ctx) {
        String clientId = plugin.getConfigManager().getGoogleClientId();
        String redirectUri = plugin.getConfigManager().getExternalUrl() + "/auth/google/callback";
        String url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=" + clientId
            + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
            + "&response_type=code&scope=" + URLEncoder.encode("openid profile email", StandardCharsets.UTF_8);
        ctx.redirect(url);
    }


    private void handleGoogleCallback(Context ctx) {
        String code = ctx.queryParam("code");
        if (code == null || code.isEmpty()) { ctx.contentType("text/html").result(renderError("Код авторизации не получен", "/login")); return; }

        try {
            // проверка vpn/гео до сессии
            String vpnError = checkVpnAndGeo(ctx);
            if (vpnError != null) { ctx.contentType("text/html"); ctx.result(vpnError); return; }

            // проверка забаненных IP
            String ipError = checkBannedIp(ipChecker.getIpFromWeb(ctx));
            if (ipError != null) { ctx.contentType("text/html"); ctx.result(ipError); return; }

            String accessToken = exchangeGoogleCode(code);
            if (accessToken == null) { ctx.contentType("text/html").result(renderError("Не удалось получить токен Google", "/login")); return; }

            GoogleUserInfo user = getGoogleUserInfo(accessToken);
            if (user == null) { ctx.contentType("text/html").result(renderError("Не удалось получить информацию Google", "/login")); return; }

            WebAccountRepository.AccountData account = findOrCreateAccount("google", user.id, user.name);
            if (account == null) { ctx.contentType("text/html").result(renderError("Не удалось создать аккаунт", "/login")); return; }

            // проверка бана
            String banError = checkAccountBan(account);
            if (banError != null) { ctx.contentType("text/html"); ctx.result(banError); return; }

            String ip = ipChecker.getIpFromWeb(ctx);
            String token = plugin.getSessionManager().createSession(account.id, ip);
            if (token == null) { ctx.contentType("text/html").result(renderError("Не удалось создать сессию", "/login")); return; }

            autoLinkNick(ctx, account);
            confirmNewIpLogin(ctx, account);
            ctx.contentType("text/html");
            ctx.result(renderProfileWithCookie(account, token));
        } catch (Exception e) {
            plugin.getLogger().severe("Ошибка Google OAuth2: " + e.getMessage());
            ctx.contentType("text/html").result(renderError("Внутренняя ошибка сервера", "/login"));
        }
    }


    private void handleVkRedirect(Context ctx) {
        String clientId = plugin.getConfigManager().getVkClientId();
        String redirectUri = plugin.getConfigManager().getExternalUrl() + "/auth/vk/callback";
        String url = "https://oauth.vk.com/authorize?client_id=" + clientId
            + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
            + "&response_type=code&scope=4194304";
        ctx.redirect(url);
    }


    private void handleVkCallback(Context ctx) {
        String code = ctx.queryParam("code");
        if (code == null || code.isEmpty()) { ctx.contentType("text/html").result(renderError("Код авторизации не получен", "/login")); return; }

        try {
            // проверка vpn/гео до сессии
            String vpnError = checkVpnAndGeo(ctx);
            if (vpnError != null) { ctx.contentType("text/html"); ctx.result(vpnError); return; }

            // проверка забаненных IP
            String ipError = checkBannedIp(ipChecker.getIpFromWeb(ctx));
            if (ipError != null) { ctx.contentType("text/html"); ctx.result(ipError); return; }

            VkTokenInfo vkToken = exchangeVkCode(code);
            if (vkToken == null || vkToken.accessToken == null) { ctx.contentType("text/html").result(renderError("Не удалось получить токен VK", "/login")); return; }

            VkUserInfo vkUser = getVkUserInfo(vkToken.accessToken, vkToken.userId);
            if (vkUser == null) { ctx.contentType("text/html").result(renderError("Не удалось получить информацию VK", "/login")); return; }

            String vkId = String.valueOf(vkUser.id);
            WebAccountRepository.AccountData account = findOrCreateAccount("vk", vkId, vkUser.firstName + " " + vkUser.lastName);
            if (account == null) { ctx.contentType("text/html").result(renderError("Не удалось создать аккаунт", "/login")); return; }

            // проверка бана
            String banError = checkAccountBan(account);
            if (banError != null) { ctx.contentType("text/html"); ctx.result(banError); return; }

            String ip = ipChecker.getIpFromWeb(ctx);
            String token = plugin.getSessionManager().createSession(account.id, ip);
            if (token == null) { ctx.contentType("text/html").result(renderError("Не удалось создать сессию", "/login")); return; }

            autoLinkNick(ctx, account);
            confirmNewIpLogin(ctx, account);
            ctx.contentType("text/html");
            ctx.result(renderProfileWithCookie(account, token));
        } catch (Exception e) {
            plugin.getLogger().severe("Ошибка VK OAuth2: " + e.getMessage());
            ctx.contentType("text/html").result(renderError("Внутренняя ошибка сервера", "/login"));
        }
    }


    private void handleTelegramRedirect(Context ctx) {
        String clientId = plugin.getConfigManager().getTelegramClientId();
        if (clientId.isEmpty()) {
            ctx.status(500).result("Telegram OAuth2 не настроен (client-id пуст)");
            return;
        }

        // PKCE code_verifier + challenge
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallengeS256(codeVerifier);

        // PKCE verifier в cookie на 10 мин
        ctx.cookie("tg_code_verifier", codeVerifier, 600);

        String redirectUri = plugin.getConfigManager().getExternalUrl() + "/auth/telegram/callback";
        // подмена URL для обхода РКН
        String tgOAuthBase = plugin.getConfigManager().getExternalUrl() + "/tg-oauth";
        String url = tgOAuthBase + "/auth?client_id=" + clientId
            + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
            + "&response_type=code"
            + "&scope=" + URLEncoder.encode("openid profile", StandardCharsets.UTF_8)
            + "&code_challenge=" + codeChallenge
            + "&code_challenge_method=S256";
        plugin.getLogger().info("[Telegram OIDC] Redirect с PKCE: code_challenge=" + codeChallenge.substring(0, Math.min(16, codeChallenge.length())) + "...");
        ctx.redirect(url);
    }


    private void handleTelegramCallback(Context ctx) {
        String code = ctx.queryParam("code");
        if (code == null || code.isEmpty()) { ctx.contentType("text/html").result(renderError("Код авторизации не получен", "/login")); return; }

        try {
            // проверка vpn/гео до сессии
            String vpnError = checkVpnAndGeo(ctx);
            if (vpnError != null) { ctx.contentType("text/html"); ctx.result(vpnError); return; }

            // проверка забаненных IP
            String ipError = checkBannedIp(ipChecker.getIpFromWeb(ctx));
            if (ipError != null) { ctx.contentType("text/html"); ctx.result(ipError); return; }

            // pkce verifier из cookie
            String codeVerifier = ctx.cookie("tg_code_verifier");
            if (codeVerifier == null || codeVerifier.isEmpty()) {
                ctx.contentType("text/html"); ctx.result(renderError("Сессия истекла.", "/login")); return;
            }
            ctx.removeCookie("tg_code_verifier");

            // меняем код на токен
            TelegramOidcToken tokenData = exchangeTelegramCode(code, codeVerifier);
            if (tokenData == null || tokenData.idToken == null) {
                ctx.contentType("text/html").result(renderError("Не удалось получить токен Telegram", "/login"));
                return;
            }

            // jwt payload
            String tgId = extractJwtClaim(tokenData.idToken, "sub");
            String tgName = extractJwtClaim(tokenData.idToken, "name");
            String tgUsername = extractJwtClaim(tokenData.idToken, "preferred_username");

            if (tgId == null || tgId.isEmpty()) {
                ctx.contentType("text/html").result(renderError("Не удалось извлечь данные из токена Telegram", "/login"));
                return;
            }

            String displayName = tgName != null ? tgName : (tgUsername != null ? tgUsername : "TG User " + tgId);
            WebAccountRepository.AccountData account = findOrCreateAccount("telegram", tgId, displayName);
            if (account == null) { ctx.contentType("text/html").result(renderError("Не удалось создать аккаунт", "/login")); return; }

            // проверка бана
            String banError = checkAccountBan(account);
            if (banError != null) { ctx.contentType("text/html"); ctx.result(banError); return; }

            String ip = ipChecker.getIpFromWeb(ctx);
            String sessionToken = plugin.getSessionManager().createSession(account.id, ip);
            if (sessionToken == null) { ctx.contentType("text/html").result(renderError("Не удалось создать сессию", "/login")); return; }

            autoLinkNick(ctx, account);
            confirmNewIpLogin(ctx, account);
            ctx.contentType("text/html");
            ctx.result(renderProfileWithCookie(account, sessionToken));
        } catch (Exception e) {
            plugin.getLogger().severe("Ошибка Telegram OIDC: " + e.getMessage());
            ctx.contentType("text/html").result(renderError("Внутренняя ошибка сервера", "/login"));
        }
    }


    private void handleProfile(Context ctx) {
        WebAccountRepository.AccountData account = getAccountFromSession(ctx);
        if (account == null) { ctx.redirect("/login"); return; }

        // проверка бана — забаненный не видит профиль
        if (account.isBanned) {
            String reason = account.banReason != null ? account.banReason : "Не указана";
            // удаляем сессию
            String token = getTokenFromRequest(ctx);
            if (token != null) plugin.getSessionManager().deleteSession(token);
            ctx.contentType("text/html");
            ctx.result(renderBanError("Ваш аккаунт заблокирован. Причина: " + reason, "/login"));
            return;
        }

        // проверка fingerprint бана
        List<FingerprintRepository.FingerprintRecord> fps = plugin.getFingerprintRepository().getFingerprintsByAccount(account.id);
        for (FingerprintRepository.FingerprintRecord fp : fps) {
            // fp забанен напрямую
            if (plugin.getFingerprintRepository().isFingerprintBanned(fp.fingerprintHash)) {
                String reason = plugin.getFingerprintRepository().getFingerprintBanReason(fp.fingerprintHash);
                banAccountFull(account.id, "Fingerprint: " + (reason != null ? reason : "?"));
                String token = getTokenFromRequest(ctx);
                if (token != null) plugin.getSessionManager().deleteSession(token);
                ctx.contentType("text/html");
                ctx.result(renderBanError("Ваш аккаунт заблокирован (fingerprint). Причина: " + (reason != null ? reason : "?"), "/login"));
                return;
            }
            // fp привязан к забаненному аккаунту
            List<Integer> linkedAccounts = plugin.getFingerprintRepository().getAccountsByFingerprint(fp.fingerprintHash);
            for (int aid : linkedAccounts) {
                if (aid != account.id) {
                    WebAccountRepository.AccountData other = plugin.getWebAccountRepository().getAccount(aid);
                    if (other != null && other.isBanned) {
                        banAccountFull(account.id, "Связанный fingerprint с забаненным аккаунтом #" + aid);
                        String token = getTokenFromRequest(ctx);
                        if (token != null) plugin.getSessionManager().deleteSession(token);
                        ctx.contentType("text/html");
                        ctx.result(renderBanError("Ваш аккаунт заблокирован (связь с забаненным аккаунтом).", "/login"));
                        return;
                    }
                }
            }
        }

        String token = getTokenFromRequest(ctx);
        ctx.contentType("text/html");
        ctx.result(renderProfile(account, token));
    }


    private void handleLinkMinecraft(Context ctx) {
        WebAccountRepository.AccountData account = getAccountFromSession(ctx);
        String token = getTokenFromRequest(ctx);
        if (account == null) { ctx.contentType("text/html"); ctx.result(renderError("Сессия истекла.", "/login")); return; }

        String nick = ctx.formParam("minecraft_nick");
        if (nick == null || nick.isEmpty() || !isValidMinecraftNick(nick)) {
            ctx.contentType("text/html"); ctx.result(renderProfileWithError(account, token, "Некорректный ник.")); return;
        }

        int existingId = plugin.getPlayerNickRepository().getAccountIdByNick(nick);
        if (existingId > 0 && existingId != account.id) {
            ctx.contentType("text/html"); ctx.result(renderProfileWithError(account, token, "Ник уже привязан к другому аккаунту.")); return;
        }

        if (!plugin.getPlayerNickRepository().linkNick(account.id, nick)) {
            ctx.contentType("text/html"); ctx.result(renderProfileWithError(account, token, "Не удалось привязать ник.")); return;
        }

        unfreezePlayer(nick);
        plugin.getDiscordNotifier().notifyNickLinked(nick, account.username);
        account = plugin.getWebAccountRepository().getAccount(account.id);
        ctx.contentType("text/html");
        ctx.result(renderProfileWithSuccess(account, token, "Ник " + nick + " добавлен!"));
    }


    private void handleUnlinkMinecraft(Context ctx) {
        WebAccountRepository.AccountData account = getAccountFromSession(ctx);
        String token = getTokenFromRequest(ctx);
        if (account == null) { ctx.contentType("text/html"); ctx.result(renderError("Сессия истекла.", "/login")); return; }

        String nick = ctx.formParam("minecraft_nick");
        if (nick == null || nick.isEmpty()) {
            ctx.contentType("text/html"); ctx.result(renderProfileWithError(account, token, "Ник не указан.")); return;
        }

        if (!plugin.getPlayerNickRepository().unlinkNick(account.id, nick)) {
            ctx.contentType("text/html"); ctx.result(renderProfileWithError(account, token, "Не удалось отвязать ник.")); return;
        }

        account = plugin.getWebAccountRepository().getAccount(account.id);
        ctx.contentType("text/html");
        ctx.result(renderProfileWithSuccess(account, token, "Ник " + nick + " убран."));
    }


    private void handleLogout(Context ctx) {
        String token = getTokenFromRequest(ctx);
        if (token != null) plugin.getSessionManager().deleteSession(token);
        ctx.contentType("text/html");
        ctx.result("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
            + "<script>document.cookie='ag_session=; path=/; max-age=0';window.location.href='/login';</script>"
            + "</head><body>Выход...</body></html>");
    }


    private void handleFingerprint(Context ctx) {
        WebAccountRepository.AccountData account = getAccountFromSession(ctx);
        if (account == null) { ctx.status(401).result("Unauthorized"); return; }

        String fpHash = ctx.formParam("fingerprint_hash");
        String browserData = ctx.formParam("browser_data");
        String deviceHash = ctx.formParam("device_hash");
        String webrtcIp = ctx.formParam("webrtc_ip");
        if (fpHash == null || fpHash.isEmpty()) { ctx.status(400).result("Missing fingerprint_hash"); return; }

        String ip = ipChecker.getIpFromWeb(ctx);

        // сохраняем браузерный отпечаток
        plugin.getFingerprintRepository().recordFingerprint(fpHash, account.id, ip, browserData);

        // сохраняем устройственный отпечаток
        if (deviceHash != null && !deviceHash.isEmpty()) {
            plugin.getDeviceFingerprintRepository().recordDeviceFingerprint(deviceHash, account.id, ip, webrtcIp);
        }

        // 1. fp забанен напрямую
        if (plugin.getFingerprintRepository().isFingerprintBanned(fpHash)) {
            String reason = plugin.getFingerprintRepository().getFingerprintBanReason(fpHash);
            banAccountFull(account.id, "Fingerprint: " + (reason != null ? reason : "?"));
            String token = getTokenFromRequest(ctx);
            if (token != null) plugin.getSessionManager().deleteSession(token);
            ctx.status(403).result("Fingerprint banned");
            return;
        }

        // 2. fp привязан к забаненному
        List<Integer> accountIds = plugin.getFingerprintRepository().getAccountsByFingerprint(fpHash);
        for (int aid : accountIds) {
            if (aid != account.id) {
                WebAccountRepository.AccountData otherAccount = plugin.getWebAccountRepository().getAccount(aid);
                if (otherAccount != null && otherAccount.isBanned) {
                    String reason = otherAccount.banReason != null ? otherAccount.banReason : "?";
                    banAccountFull(account.id, "Связанный fingerprint с забаненным аккаунтом #" + aid + ": " + reason);
                    String token = getTokenFromRequest(ctx);
                    if (token != null) plugin.getSessionManager().deleteSession(token);
                    ctx.status(403).result("Linked to banned account");
                    return;
                }
            }
        }

        // 3. устройство забанено
        if (deviceHash != null && !deviceHash.isEmpty()) {
            if (plugin.getDeviceFingerprintRepository().isDeviceBanned(deviceHash)) {
                String reason = plugin.getDeviceFingerprintRepository().getDeviceBanReason(deviceHash);
                banAccountFull(account.id, "Устройство забанено: " + (reason != null ? reason : "?"));
                String token = getTokenFromRequest(ctx);
                if (token != null) plugin.getSessionManager().deleteSession(token);
                ctx.status(403).result("Device banned");
                return;
            }

            // 4. устройство привязано к забаненному
            List<Integer> deviceAccounts = plugin.getDeviceFingerprintRepository().getAccountsByDevice(deviceHash);
            for (int aid : deviceAccounts) {
                if (aid != account.id) {
                    WebAccountRepository.AccountData otherAccount = plugin.getWebAccountRepository().getAccount(aid);
                    if (otherAccount != null && otherAccount.isBanned) {
                        String reason = otherAccount.banReason != null ? otherAccount.banReason : "?";
                        banAccountFull(account.id, "Связанное устройство с забаненным аккаунтом #" + aid + ": " + reason);
                        String token = getTokenFromRequest(ctx);
                        if (token != null) plugin.getSessionManager().deleteSession(token);
                        ctx.status(403).result("Device linked to banned account");
                        return;
                    }
                }
            }
        }

        ctx.status(200).result("OK");
    }


    private void handleCheckBan(Context ctx) {
        // проверяем по сессии
        WebAccountRepository.AccountData account = getAccountFromSession(ctx);
        if (account == null) {
            // нет сессии — маркер устарел
            ctx.status(200).result("OK");
            return;
        }

        // аккаунт забанен?
        if (account.isBanned) {
            ctx.status(403).result("Banned");
            return;
        }

        // fingerprint забанен?
        List<FingerprintRepository.FingerprintRecord> fps =
            plugin.getFingerprintRepository().getFingerprintsByAccount(account.id);
        for (FingerprintRepository.FingerprintRecord fp : fps) {
            if (plugin.getFingerprintRepository().isFingerprintBanned(fp.fingerprintHash)) {
                ctx.status(403).result("Fingerprint banned");
                return;
            }
        }

        // device забанен?
        List<DeviceFingerprintRepository.DeviceFingerprintRecord> deviceFps =
            plugin.getDeviceFingerprintRepository().getDeviceFingerprintsByAccount(account.id);
        for (DeviceFingerprintRepository.DeviceFingerprintRecord dfp : deviceFps) {
            if (plugin.getDeviceFingerprintRepository().isDeviceBanned(dfp.deviceHash)) {
                ctx.status(403).result("Device banned");
                return;
            }
        }

        // ip забанен?
        String ip = ipChecker.getIpFromWeb(ctx);
        if (ip != null && !isLocalIp(ip)) {
            var ipBan = plugin.getIpBanRepository().getActiveBan(ip);
            if (ipBan != null) {
                ctx.status(403).result("IP banned");
                return;
            }
        }

        // бана нет — маркер устарел
        ctx.status(200).result("OK");
    }


    private void handleStyleCss(Context ctx) {
        ctx.contentType("text/css");
        ctx.result(CSS);
    }

    // локально, без CDN
    private void handleFpJs(Context ctx) {
        ctx.contentType("application/javascript");
        ctx.header("Cache-Control", "public, max-age=86400");
        ctx.result(FP_JS);
    }

    // ==================== Админ-панель ====================



    // ==================== OAuth2 API ====================





    // ==================== OAuth2 API ====================


    private String exchangeDiscordCode(String code) {
        String clientId = plugin.getConfigManager().getDiscordClientId();
        String clientSecret = plugin.getConfigManager().getDiscordClientSecret();
        String redirectUri = plugin.getConfigManager().getExternalUrl() + "/auth/discord/callback";
        String body = "client_id=" + clientId + "&client_secret=" + clientSecret
            + "&grant_type=authorization_code&code=" + code
            + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
        return exchangeCode("https://discord.com/api/v10/oauth2/token", body);
    }


    private DiscordUserInfo getDiscordUserInfo(String accessToken) {
        try {
            String json = httpGet("https://discord.com/api/v10/users/@me", accessToken);
            JsonNode node = objectMapper.readTree(json);
            DiscordUserInfo info = new DiscordUserInfo();
            info.id = node.path("id").asText();
            info.username = node.path("username").asText("Discord User");
            return info;
        } catch (Exception e) { return null; }
    }


    private String exchangeGoogleCode(String code) {
        String clientId = plugin.getConfigManager().getGoogleClientId();
        String clientSecret = plugin.getConfigManager().getGoogleClientSecret();
        String redirectUri = plugin.getConfigManager().getExternalUrl() + "/auth/google/callback";
        String body = "client_id=" + clientId + "&client_secret=" + clientSecret
            + "&grant_type=authorization_code&code=" + code
            + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
        return exchangeCode("https://oauth2.googleapis.com/token", body);
    }


    private GoogleUserInfo getGoogleUserInfo(String accessToken) {
        try {
            String json = httpGet("https://www.googleapis.com/oauth2/v2/userinfo", accessToken);
            JsonNode node = objectMapper.readTree(json);
            GoogleUserInfo info = new GoogleUserInfo();
            info.id = node.path("id").asText();
            info.name = node.path("name").asText("Google User");
            info.email = node.path("email").asText(null);
            return info;
        } catch (Exception e) { return null; }
    }


    private VkTokenInfo exchangeVkCode(String code) {
        String clientId = plugin.getConfigManager().getVkClientId();
        String clientSecret = plugin.getConfigManager().getVkClientSecret();
        String redirectUri = plugin.getConfigManager().getExternalUrl() + "/auth/vk/callback";
        String url = "https://oauth.vk.com/access_token?client_id=" + clientId
            + "&client_secret=" + clientSecret
            + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
            + "&code=" + code;
        try {
            String json = httpGet(url, null);
            JsonNode node = objectMapper.readTree(json);
            VkTokenInfo info = new VkTokenInfo();
            info.accessToken = node.path("access_token").asText(null);
            info.userId = node.path("user_id").asInt(0);
            return info;
        } catch (Exception e) { return null; }
    }


    private VkUserInfo getVkUserInfo(String accessToken, int userId) {
        String url = "https://api.vk.com/method/users.get?user_ids=" + userId
            + "&fields=first_name,last_name&access_token=" + accessToken + "&v=5.131";
        try {
            String json = httpGet(url, null);
            JsonNode node = objectMapper.readTree(json);
            JsonNode arr = node.path("response");
            if (arr.isArray() && arr.size() > 0) {
                JsonNode user = arr.get(0);
                VkUserInfo info = new VkUserInfo();
                info.id = user.path("id").asInt();
                info.firstName = user.path("first_name").asText("");
                info.lastName = user.path("last_name").asText("");
                return info;
            }
            return null;
        } catch (Exception e) { return null; }
    }


    private String exchangeCode(String url, String body) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .timeout(Duration.ofSeconds(10))
                .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            JsonNode node = objectMapper.readTree(response.body());
            return node.path("access_token").asText(null);
        } catch (Exception e) {
            plugin.getLogger().severe("Ошибка обмена кода: " + e.getMessage());
            return null;
        }
    }


    private String httpGet(String url, String bearer) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(10))
                .GET();
            if (bearer != null) builder.header("Authorization", "Bearer " + bearer);
            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            return response.body();
        } catch (Exception e) {
            plugin.getLogger().severe("Ошибка HTTP GET: " + e.getMessage());
            return null;
        }
    }

    // ==================== PKCE утилиты ====================


    private static String generateCodeVerifier() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }


    private static String generateCodeChallengeS256(String codeVerifier) {
        try {
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256")
                .digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 недоступен", e);
        }
    }

    // ==================== DTO ====================

    private static class DiscordUserInfo { String id; String username; }
    private static class GoogleUserInfo { String id; String name; String email; }
    private static class VkTokenInfo { String accessToken; int userId; }
    private static class VkUserInfo { int id; String firstName; String lastName; }

    // ==================== Telegram OIDC ====================


    private static class TelegramOidcToken {
        String accessToken;
        String idToken;
    }

    // OIDC + PKCE
    private TelegramOidcToken exchangeTelegramCode(String code, String codeVerifier) {
        String clientId = plugin.getConfigManager().getTelegramClientId();
        String clientSecret = plugin.getConfigManager().getTelegramClientSecret();
        String redirectUri = plugin.getConfigManager().getExternalUrl() + "/auth/telegram/callback";

        // PKCE
        String credentials = java.util.Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        String body = "grant_type=authorization_code"
            + "&code=" + code
            + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
            + "&client_id=" + clientId
            + "&code_verifier=" + URLEncoder.encode(codeVerifier, StandardCharsets.UTF_8);

        try {
            plugin.getLogger().info("[Telegram OIDC] Обмен кода на токен: client_id=" + clientId + " redirect_uri=" + redirectUri + " code_verifier=" + (codeVerifier != null ? codeVerifier.substring(0, Math.min(16, codeVerifier.length())) + "..." : "NULL"));

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://oauth.telegram.org/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + credentials)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .timeout(Duration.ofSeconds(30))
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            plugin.getLogger().info("[Telegram OIDC] Ответ: HTTP " + response.statusCode() + " body=" + response.body());

            JsonNode node = objectMapper.readTree(response.body());

            // проверяем ошибку
            if (node.has("error")) {
                String error = node.path("error").asText();
                String errorDesc = node.path("error_description").asText("");
                plugin.getLogger().severe("[Telegram OIDC] Ошибка: " + error + " — " + errorDesc);
                return null;
            }

            TelegramOidcToken result = new TelegramOidcToken();
            result.accessToken = node.path("access_token").asText(null);
            result.idToken = node.path("id_token").asText(null);

            if (result.accessToken == null && result.idToken == null) {
                plugin.getLogger().severe("[Telegram OIDC] Нет access_token и id_token в ответе. Полный ответ: " + response.body());
                return null;
            }

            return result;
        } catch (Exception e) {
            plugin.getLogger().severe("Ошибка обмена Telegram кода: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    // без проверки подписи
    private String extractJwtClaim(String jwt, String claim) {
        try {
            // jwt payload без подписи
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) return null;
            // base64url payload
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
            JsonNode node = objectMapper.readTree(payload);
            return node.path(claim).asText(null);
        } catch (Exception e) {
            plugin.getLogger().warning("Ошибка парсинга JWT: " + e.getMessage());
            return null;
        }
    }

    // ==================== Вспомогательные методы ====================


    private WebAccountRepository.AccountData findOrCreateAccount(String provider, String socialId, String username) {
        WebAccountRepository repo = plugin.getWebAccountRepository();
        WebAccountRepository.AccountData account = switch (provider) {
            case "discord" -> repo.getAccountByDiscordId(socialId);
            case "google" -> repo.getAccountByGoogleId(socialId);
            case "vk" -> repo.getAccountByVkId(socialId);
            case "telegram" -> repo.getAccountByTelegramId(socialId);
            default -> null;
        };
        if (account == null) {
            int id = repo.createAccount(
                "discord".equals(provider) ? socialId : null,
                "google".equals(provider) ? socialId : null,
                "vk".equals(provider) ? socialId : null,
                "telegram".equals(provider) ? socialId : null,
                username
            );
            if (id <= 0) return null;
            account = repo.getAccount(id);
        }
        return account;
    }


    private void autoLinkNick(Context ctx, WebAccountRepository.AccountData account) {
        String nick = ctx.cookie("ag_minecraft_nick");
        if (nick != null && !nick.isEmpty()) {
            if (plugin.getPlayerNickRepository().linkNick(account.id, nick)) {
                ctx.removeCookie("ag_minecraft_nick");
                unfreezePlayer(nick);
                plugin.getDiscordNotifier().notifyAccountLinked(nick, account.username);
            }
        }
    }

    // размораживаем ники при логине через oauth (подтверждает владельца)
    private void confirmNewIpLogin(Context ctx, WebAccountRepository.AccountData account) {
        String webIp = ipChecker.getIpFromWeb(ctx);
        if (webIp == null || webIp.isEmpty()) return;

        java.util.List<String> nicks = plugin.getPlayerNickRepository().getNicksByAccount(account.id);
        for (String nick : nicks) {
            if (plugin.getFrozenPlayers().contains(nick)) {
                unfreezePlayer(nick);
                plugin.getPlayerIpRepository().recordIp(nick, webIp);
                plugin.getLogger().info("[Web] " + nick + " разморожен — владелец подтвердил вход через OAuth2 (IP=" + webIp + ")");
            }
        }
    }


    private boolean isLocalIp(String ip) {
        return ip.startsWith("127.") || ip.startsWith("10.") ||
               ip.startsWith("192.168.") || ip.equals("0.0.0.0") ||
               ip.startsWith("172.16.") || ip.startsWith("172.17.") ||
               ip.startsWith("172.18.") || ip.startsWith("172.19.") ||
               ip.startsWith("172.2") || ip.startsWith("172.3") ||
               ip.equals("::1") || ip.equals("localhost");
    }

    // null = ок, иначе html ошибки
    private String checkVpnAndGeo(Context ctx) {
        if (!plugin.getConfigManager().isVpnCheckEnabled()) return null;

        String ip = ipChecker.getIpFromWeb(ctx);
        plugin.getLogger().info("[Web] checkVpnAndGeo IP=" + ip + " isLocal=" + isLocalIp(ip));

        // локальные IP пропускаем (dev)
        if (isLocalIp(ip)) return null;

        VpnChecker.VpnResult vpnResult = plugin.getVpnChecker().check(ip);

        // проверка vpn/прокси
        if (!vpnResult.isError && vpnResult.isVpn) {
            plugin.getLogger().info("[Web] VPN/прокси отклонён: " + ip);
            return renderError(
                "Использование VPN/прокси запрещено. Отключите VPN и попробуйте снова.",
                "/login"
            );
        }

        // проверка страны (СНГ)
        if (!vpnResult.isError && vpnResult.country != null) {
            if (!plugin.getGeoFilter().isCountryAllowed(vpnResult.country)) {
                plugin.getLogger().info("[Web] Страна отклонена: " + ip + " (" + vpnResult.country + ")");
                return renderError(
                    "Доступ только для стран СНГ. Ваш регион: " + vpnResult.country,
                    "/login"
                );
            }
        }

        return null;
    }

    // null = не забанен, иначе html ошибки
    private String checkAccountBan(WebAccountRepository.AccountData account) {
        if (account.isBanned) {
            String reason = account.banReason != null ? account.banReason : "Не указана";
            plugin.getLogger().info("[Web] Забаненный аккаунт отклонён: " + account.username + " (" + reason + ")");
            return renderBanError(
                "Ваш аккаунт заблокирован. Причина: " + reason,
                "/login"
            );
        }
        return null;
    }

    // банит аккаунт + все его fingerprints/devices + все аккаунты с ними
    private void banAccountFull(int accountId, String reason) {
        // бан аккаунта + все его fp/devices + аккаунты с ними
        plugin.getWebAccountRepository().banAccount(accountId, reason);

        // discord нотификация (без бана на сервере — можно обжаловать)
        WebAccountRepository.AccountData account = plugin.getWebAccountRepository().getAccount(accountId);
        if (account != null) {
            plugin.getDiscordNotifier().notifyBanNick("Admin(Web)", account.username, 0, reason, "перманентно", true);
        }

        // 3. получаем все fp аккаунта
        List<FingerprintRepository.FingerprintRecord> fps =
            plugin.getFingerprintRepository().getFingerprintsByAccount(accountId);

        // баним все fp + аккаунты с ними
        for (FingerprintRepository.FingerprintRecord fp : fps) {
            plugin.getFingerprintRepository().banFingerprint(fp.fingerprintHash, reason);

            // бан аккаунтов с этим fp
            List<Integer> accountIds = plugin.getFingerprintRepository().getAccountsByFingerprint(fp.fingerprintHash);
            for (int aid : accountIds) {
                if (aid != accountId) {
                    plugin.getWebAccountRepository().banAccount(aid, "Связанный fingerprint: " + reason);
                }
            }
        }

        // баним все device + аккаунты с ними
        List<DeviceFingerprintRepository.DeviceFingerprintRecord> deviceFps =
            plugin.getDeviceFingerprintRepository().getDeviceFingerprintsByAccount(accountId);
        for (DeviceFingerprintRepository.DeviceFingerprintRecord dfp : deviceFps) {
            plugin.getDeviceFingerprintRepository().banDevice(dfp.deviceHash, reason);

            // бан аккаунтов с этим device
            List<Integer> deviceAccountIds = plugin.getDeviceFingerprintRepository().getAccountsByDevice(dfp.deviceHash);
            for (int aid : deviceAccountIds) {
                if (aid != accountId) {
                    plugin.getWebAccountRepository().banAccount(aid, "Связанное устройство: " + reason);
                }
            }
        }

        plugin.getLogger().info("[Ban] Полный бан аккаунта #" + accountId + ": " + reason
            + " (fingerprints: " + fps.size() + ", devices: " + deviceFps.size() + ")");
    }

    // null = IP чистый, иначе html ошибки
    private String checkBannedIp(String ip) {
        // локальные IP пропускаем
        if (isLocalIp(ip)) return null;

        // fingerprints по IP
        int bannedId = plugin.getFingerprintRepository().getBannedAccountIdByIp(ip);
        if (bannedId > 0) {
            plugin.getLogger().info("[Web] IP забаненного аккаунта: " + ip + " (аккаунт #" + bannedId + ")");
            return renderBanError(
                "Ваш IP-адрес связан с заблокированным аккаунтом. Обратитесь к администрации.",
                "/login"
            );
        }

        // player_ips по IP
        List<String> nicksWithIp = plugin.getPlayerIpRepository().getNicksByIp(ip);
        for (String nick : nicksWithIp) {
            WebAccountRepository.AccountData nickAccount = plugin.getWebAccountRepository().getAccountByNick(nick);
            if (nickAccount != null && nickAccount.isBanned) {
                plugin.getLogger().info("[Web] IP забаненного игрока: " + ip + " (ник: " + nick + ")");
                return renderBanError(
                    "Ваш IP-адрес связан с заблокированным аккаунтом. Обратитесь к администрации.",
                    "/login"
                );
            }
        }

        return null;
    }

    private void unfreezePlayer(String nick) {
        if (plugin.getFrozenPlayers().remove(nick)) {
            plugin.getDiscordNotifier().notifyUnfrozen(nick, "Подтверждение через OAuth2 на сайте");
        }
        plugin.getServer().getGlobalRegionScheduler().run(plugin, task -> {
            org.bukkit.entity.Player player = plugin.getServer().getPlayer(nick);
            if (player != null && player.isOnline()) {
                String msg = plugin.getConfigManager().getGameLinkSuccess();
                player.sendMessage(net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer
                    .legacyAmpersand().deserialize(msg));
            }
        });
    }


    private boolean isValidMinecraftNick(String nick) {
        return nick != null && nick.matches("^[a-zA-Z0-9_]{3,16}$");
    }


    private String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    // ==================== SVG Иконки брендов ====================


    private static final String SVG_DISCORD = "<svg xmlns='http://www.w3.org/2000/svg' width='22' height='22' viewBox='0 0 24 24' fill='white'><path d='M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.568-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z'/></svg>";


    private static final String SVG_GOOGLE = "<svg xmlns='http://www.w3.org/2000/svg' width='22' height='22' viewBox='0 0 24 24'><circle cx='12' cy='12' r='12' fill='#fff'/><path d='M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z' fill='#4285F4'/><path d='M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z' fill='#34A853'/><path d='M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z' fill='#FBBC05'/><path d='M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z' fill='#EA4335'/></svg>";


    private static final String SVG_TELEGRAM = "<svg xmlns='http://www.w3.org/2000/svg' width='22' height='22' viewBox='0 0 24 24' fill='white'><path d='M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.479.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z'/></svg>";


    private static final String SVG_DISCORD_SM = "<svg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='currentColor'><path d='M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.568-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z'/></svg>";
    private static final String SVG_GOOGLE_SM = "<svg class='google-icon' xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24'><circle cx='12' cy='12' r='12' fill='#fff'/><path d='M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z' fill='#4285F4'/><path d='M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z' fill='#34A853'/><path d='M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z' fill='#FBBC05'/><path d='M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z' fill='#EA4335'/></svg>";
    private static final String SVG_TELEGRAM_SM = "<svg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='currentColor'><path d='M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.479.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z'/></svg>";

    // ==================== CSS ====================

    private static final String CSS = """
        @import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        :root {
            --mc-yellow: #ffff55; --mc-gold: #ffaa00; --mc-gold-dk: #aa7700;
            --mc-green: #55ff55; --mc-green-dk: #2a802a; --mc-white: #f4f4f4;
            --mc-gray: #c6c6c6; --discord: #5865F2; --google: #4285F4; --telegram: #26A5E4;
        }
        html, body { height: 100%; }
        body {
            font-family: 'Press Start 2P', monospace; color: var(--mc-white); font-size: 12px;
            min-height: 100vh;
            background: #1a1a1a;
            background-image: radial-gradient(ellipse at 50% 30%, #2d2d2d 0%, #0d0d0d 100%);
            background-attachment: fixed;
            position: relative; display: flex; flex-direction: column; align-items: center;
            padding: 24px 14px 0; box-sizing: border-box;
        }
        body::before {
            content: ""; position: fixed; inset: 0;
            background: radial-gradient(ellipse at 50% 30%, rgba(0,0,0,.05), rgba(0,0,0,.35) 95%);
            pointer-events: none; z-index: 0;
        }
        .container { position: relative; z-index: 1; width: 100%; max-width: 540px; display: flex; flex-direction: column; align-items: center; flex: 1; }
        .card {
            width: 100%;
            background: repeating-linear-gradient(0deg, rgba(0,0,0,.05) 0 2px, rgba(255,255,255,.04) 2px 4px), #313131;
            border: 4px solid #000;
            box-shadow: inset 4px 4px 0 0 #5a5a5a, inset -4px -4px 0 0 #1a1a1a, 0 0 0 4px #000, 0 10px 0 0 rgba(0,0,0,.35);
            padding: 26px 22px; margin-bottom: 22px;
        }
        .card--ender {
            background: repeating-linear-gradient(0deg, rgba(255,255,255,.03) 0 2px, rgba(0,0,0,.10) 2px 4px), #2d1b3d;
            box-shadow: inset 4px 4px 0 0 #6b4a8a, inset -4px -4px 0 0 #160d20, 0 0 0 4px #000, 0 10px 0 0 rgba(0,0,0,.4);
        }
        .card-title {
            font-size: 13px; color: var(--mc-yellow);
            text-shadow: 2px 2px 0 #3a2800;
            text-align: center; margin-bottom: 18px; line-height: 1.6;
        }
        .card-title--ender { color: #d98aff; text-shadow: 2px 2px 0 #1a0a26; }
        .card-subtitle {
            color: var(--mc-gray); font-size: 10px; margin-bottom: 12px;
            text-shadow: 1px 1px 0 #000;
        }
        .btn {
            display: flex; align-items: center; justify-content: center; gap: 10px;
            width: 100%; padding: 14px 16px;
            font-family: 'Press Start 2P', monospace; font-size: 11px; line-height: 1.6;
            color: var(--mc-white); text-shadow: 2px 2px 0 #1a1a1a;
            text-decoration: none; cursor: pointer; border: none;
            background: linear-gradient(180deg, #a3a3a3 0%, #8b8b8b 45%, #6f6f6f 100%);
            box-shadow: inset 3px 3px 0 0 #e2e2e2, inset -3px -3px 0 0 #4a4a4a, 0 4px 0 0 #2b2b2b;
            transition: filter .05s linear, transform .05s linear; user-select: none;
        }
        .btn:hover { filter: brightness(1.18); background: linear-gradient(180deg, #b9b9b9 0%, #9d9d9d 45%, #7c7c7c 100%); color: var(--mc-yellow); }
        .btn:active { transform: translateY(4px); box-shadow: inset 3px 3px 0 0 #4a4a4a, inset -3px -3px 0 0 #e2e2e2, 0 0 0 0 #2b2b2b; }
        .btn svg { width: 22px; height: 22px; flex: 0 0 22px; }
        .btn-discord { background: linear-gradient(180deg, #7782ff 0%, #5865F2 45%, #3c47c9 100%); box-shadow: inset 3px 3px 0 0 #aab0ff, inset -3px -3px 0 0 #2a338f, 0 4px 0 0 #1d2360; }
        .btn-discord:hover { filter: brightness(1.15); color: #fff; }
        .btn-google { background: linear-gradient(180deg, #6fa3ff 0%, #4285F4 45%, #2b66cc 100%); box-shadow: inset 3px 3px 0 0 #a9c8ff, inset -3px -3px 0 0 #1f4d9e, 0 4px 0 0 #143566; }
        .btn-google:hover { filter: brightness(1.15); color: #fff; }
        .btn-telegram { background: linear-gradient(180deg, #5bc2f0 0%, #26A5E4 45%, #1782b8 100%); box-shadow: inset 3px 3px 0 0 #9ad9f7, inset -3px -3px 0 0 #115f88, 0 4px 0 0 #0c4561; }
        .btn-telegram:hover { filter: brightness(1.15); color: #fff; }
        .btn-green { background: linear-gradient(180deg, #7ab83a 0%, #5a8a22 45%, #3a6010 100%); box-shadow: inset 3px 3px 0 0 #a0d060, inset -3px -3px 0 0 #2a5010, 0 4px 0 0 #1a3008; }
        .btn-green:hover { filter: brightness(1.15); color: #fff; }
        .btn-red { background: linear-gradient(180deg, #e06666 0%, #c0392b 45%, #8e2820 100%); box-shadow: inset 3px 3px 0 0 #ff9d9d, inset -3px -3px 0 0 #6e1e16, 0 4px 0 0 #4d150f; }
        .btn-red:hover { filter: brightness(1.15); color: #fff; }
        .btn-small { font-size: 10px; padding: 10px 14px; margin: 0; width: auto; }
        .input-field {
            width: 100%; font-family: 'Press Start 2P', monospace;
            font-size: 11px; color: var(--mc-green); text-shadow: 1px 1px 0 var(--mc-green-dk);
            background: #5a5a5a; border: none; padding: 14px 12px;
            box-shadow: inset 3px 3px 0 0 #2b2b2b, inset -3px -3px 0 0 #8f8f8f, 0 0 0 3px #000;
            outline: none;
        }
        .input-field:focus { background: #666; box-shadow: inset 3px 3px 0 0 #2b2b2b, inset -3px -3px 0 0 #8f8f8f, 0 0 0 3px var(--mc-yellow); }
        .input-field::placeholder { color: #cfcfcf; opacity: .7; }
        .nick-list { list-style: none; display: flex; flex-direction: column; gap: 8px; }
        .nick-item { display: flex; align-items: center; gap: 10px; font-size: 11px; color: var(--mc-green); text-shadow: 2px 2px 0 var(--mc-green-dk); background: linear-gradient(180deg, rgba(0,0,0,.35), rgba(0,0,0,.15)); border: 2px solid #000; box-shadow: inset 2px 2px 0 #2a2a2a, inset -2px -2px 0 #000; padding: 11px 12px; }
        .nick-item .grass { width: 18px; height: 18px; flex: 0 0 18px; background: linear-gradient(180deg, #5fae3a 0 35%, #7a5234 35% 100%); border: 1px solid #000; }
        .nick-name { flex: 1; color: var(--mc-green); font-size: 11px; text-shadow: 2px 2px 0 var(--mc-green-dk); }
        .msg-success { color: var(--mc-green); padding: 12px; background: #1a3a1a; border: 4px solid #000; box-shadow: inset 3px 3px 0 0 #4a8a4a, inset -3px -3px 0 0 #1a4a1a, 0 0 0 3px #000; margin-bottom: 12px; text-shadow: 1px 1px 0 #003300; text-align: center; }
        .msg-error { color: #ff5555; padding: 12px; background: #3a1a1a; border: 4px solid #000; box-shadow: inset 3px 3px 0 0 #8a4444, inset -3px -3px 0 0 #4a1515, 0 0 0 3px #000; margin-bottom: 12px; text-shadow: 1px 1px 0 #330000; text-align: center; }
        .error-cube { width: 64px; height: 64px; margin: 0 auto 18px; background: linear-gradient(180deg, #e06666, #8e2820); border: 4px solid #1a1a1a; box-shadow: inset 3px 3px 0 rgba(255,255,255,.3), inset -3px -3px 0 rgba(0,0,0,.5); display: flex; align-items: center; justify-content: center; font-size: 30px; animation: shake 2.4s ease-in-out infinite; }
        @keyframes shake { 0%, 92%, 100% { transform: translateX(0) rotate(0); } 94% { transform: translateX(-3px) rotate(-3deg); } 96% { transform: translateX(3px) rotate(3deg); } 98% { transform: translateX(-2px) rotate(-1deg); } }
        .error-msg { font-size: 11px; color: #ff9d9d; text-shadow: 2px 2px 0 #3a0e0e; text-align: center; line-height: 1.9; }
        .social-icons { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 14px; }
        .social-icon { display: inline-flex; align-items: center; gap: 6px; padding: 5px 10px; font-size: 8px; border: 2px solid #1a1a1a; box-shadow: inset 2px 2px 0 rgba(255,255,255,.15), inset -2px -2px 0 rgba(0,0,0,.3); }
        .social-icon svg { width: 14px; height: 14px; }
        .social-icon.linked { color: var(--mc-green); background: #1a3a1a; border-color: #2d6a2d; }
        .social-icon.not-linked { color: #6b5a2a; background: #1a1005; border-color: #4a3510; }
        .footer { position: relative; z-index: 1; margin-top: auto; padding: 22px 10px; text-align: center; color: var(--mc-gray); font-size: 8px; text-shadow: 1px 1px 0 #000; line-height: 2; width: 100%; flex-shrink: 0; }
        .footer b { color: var(--mc-yellow); }
        .login-buttons { display: flex; flex-direction: column; gap: 12px; margin-top: 20px; }
        .login-buttons .btn { width: 100%; }
        .add-nick-form { display: flex; gap: 12px; align-items: stretch; margin-top: 14px; flex-wrap: wrap; }
        .add-nick-form .input-field { flex: 1; min-width: 180px; }
        .add-nick-form .btn { width: auto; padding: 14px 18px; white-space: nowrap; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 6px 8px; border: 2px solid #1a1a1a; text-align: left; font-size: 10px; }
        th { background: #313131; color: var(--mc-yellow); text-shadow: 1px 1px 0 #1a1a1a; }
        td { background: #1a1a1a; }
        .banned { color: #ff5555; text-shadow: 1px 1px 0 #330000; }
        .not-banned { color: var(--mc-green); text-shadow: 1px 1px 0 #003300; }
        .mc-divider { height: 8px; margin: 20px 0; width: 100%; background: linear-gradient(180deg, #1a1a1a 0 2px, #5a5a5a 2px 4px, #373737 4px 6px, #1a1a1a 6px 8px); border-radius: 1px; }
        .mc-splash { position: absolute; left: 50%; top: 24px; margin-left: 92px; font-size: 11px; color: var(--mc-yellow); text-shadow: 2px 2px 0 #3a2800; transform: rotate(-16deg); transform-origin: left center; white-space: nowrap; pointer-events: none; z-index: 2; animation: splashPulse 1s ease-in-out infinite; }
        @keyframes splashPulse { 0%, 100% { transform: rotate(-16deg) scale(1); } 50% { transform: rotate(-16deg) scale(1.10); } }
        .title-block { position: relative; display: block; text-align: center; margin: 24px 0 14px; }
        .mc-title { font-size: 30px; line-height: 1.35; text-align: center; color: var(--mc-gold); letter-spacing: 1px; margin: 0; text-shadow: 4px 4px 0 var(--mc-gold-dk), 4px 4px 0 #3a2800; }
        .mc-subtitle { font-size: 9px; color: var(--mc-yellow); text-shadow: 2px 2px 0 #3a2800; text-align: center; margin-bottom: 26px; line-height: 1.7; }
        .login-header { text-align: center; margin-bottom: 8px; }
        .login-header .server-name { color: var(--mc-gold); font-size: 22px; text-shadow: 4px 4px 0 var(--mc-gold-dk), 4px 4px 0 #3a2800; letter-spacing: 2px; }
        .login-header .server-ip { color: var(--mc-green); font-size: 10px; margin-top: 6px; text-shadow: 1px 1px 0 var(--mc-green-dk); }
        .profile-avatar { width: 56px; height: 56px; flex: 0 0 56px; image-rendering: pixelated; border: 3px solid #1a1a1a; box-shadow: inset 0 0 0 1px #000, 3px 3px 0 rgba(0,0,0,.5); }
        .profile-header { display: flex; align-items: center; gap: 16px; margin-bottom: 12px; flex-wrap: wrap; }
        .profile-name { color: var(--mc-gold); font-size: 14px; text-shadow: 2px 2px 0 #3a2800; line-height: 1.6; }
        .profile-sub { font-size: 8px; color: var(--mc-green); text-shadow: 1px 1px 0 var(--mc-green-dk); margin-top: 8px; line-height: 1.8; }
        .nick-skin { display: inline-block; width: 16px; height: 16px; background: var(--mc-green); margin-right: 6px; image-rendering: pixelated; vertical-align: middle; }
        .nick-remove { font-family: inherit; font-size: 9px; color: #ff8a8a; background: #5a1f1a; border: 2px solid #000; box-shadow: inset 1px 1px 0 #a04040, inset -1px -1px 0 #2a0f0c; padding: 5px 8px; cursor: pointer; text-shadow: 1px 1px 0 #000; }
        .nick-remove:hover { filter: brightness(1.25); }
        .nick-empty { font-size: 9px; color: var(--mc-gray); line-height: 1.9; text-align: center; padding: 8px; }
        .section-label { font-size: 10px; color: var(--mc-yellow); text-shadow: 2px 2px 0 #3a2800; margin-bottom: 12px; }
        @media (max-width: 520px) { .mc-title { font-size: 20px; } .btn { font-size: 10px; padding: 12px 10px; } .card { padding: 20px 14px; } .add-nick-form { flex-direction: column; } .add-nick-form .btn { width: 100%; } .profile-name { font-size: 12px; } }
        @media (max-width: 360px) { .mc-title { font-size: 16px; } .btn { font-size: 9px; } }
        """;

    // ==================== HTML Рендеринг ====================


    private String renderLoginPage() {
        boolean hasDiscord = !plugin.getConfigManager().getDiscordClientId().isEmpty();
        boolean hasGoogle = !plugin.getConfigManager().getGoogleClientId().isEmpty();
        boolean hasVk = !plugin.getConfigManager().getVkClientId().isEmpty();
        boolean hasTelegram = !plugin.getConfigManager().getTelegramClientId().isEmpty()
            && !plugin.getConfigManager().getTelegramClientSecret().isEmpty();

        StringBuilder buttons = new StringBuilder();
        if (hasDiscord) buttons.append("<a href='/auth/discord' class='btn btn-discord'>").append(SVG_DISCORD).append("Войти через Discord</a>");
        if (hasGoogle) buttons.append("<a href='/auth/google' class='btn btn-google'>").append(SVG_GOOGLE).append("Войти через Google</a>");
        if (hasVk) buttons.append("<a href='/auth/vk' class='btn btn-telegram'>Войти через VK</a>");
        if (hasTelegram) buttons.append("<a href='/auth/telegram' class='btn btn-telegram'>").append(SVG_TELEGRAM).append("Войти через Telegram</a>");
        if (buttons.isEmpty()) buttons.append("<p style='color:#ff4444'>OAuth2 не настроен.</p>");

        return htmlPage("\u26CF Вход — VNLLA.RU",
            "<div class='title-block'>"
            + "<h1 class='mc-title'>VNLLA.RU</h1>"
            + "<span class='mc-splash'>Высокий TPS!</span>"
            + "</div>"
            + "<p class='mc-subtitle'>// СЕРВЕР MINECRAFT //<br>Войдите, чтобы продолжить</p>"
            + "<div class='card card--ender'>"
            + "<p class='card-title card-title--ender'>\u26CF ВХОД В АККАУНТ \u26CF</p>"
            + "<div class='login-buttons'>" + buttons + "</div>"
            + "<div class='mc-divider'></div>"
            + "<p style='font-size:9px;color:var(--mc-gray);text-align:center'>Авторизуясь, вы принимаете правила сервера</p>"
            + "</div>"
        );
    }

    // telegram oidc вместо виджета

    // с установкой cookie через JS
    private String renderProfileWithCookie(WebAccountRepository.AccountData account, String token) {
        return htmlPage("Профиль — VNLLA.RU",
            "<div id='profile-wrap' style='display:none'>" + profileContent(account, token) + "</div>"
            + "<div id='fp-loading' style='text-align:center;padding:60px 0'><p style='color:#aaa;font-size:18px'>\u23F3 Проверка безопасности...</p></div>"
            + "<script>"
            + "document.cookie='ag_session=" + token + "; path=/; max-age=" + plugin.getSessionManager().getSessionMaxAge() + "; SameSite=Lax';"
            + "history.replaceState(null,'','/profile');"
            + "collectFingerprintSecure('" + token + "');"
            + "</script>"
        );
    }


    private String renderProfile(WebAccountRepository.AccountData account, String token) {
        return htmlPage("Профиль — VNLLA.RU",
            "<div id='profile-wrap' style='display:none'>" + profileContent(account, token) + "</div>"
            + "<div id='fp-loading' style='text-align:center;padding:60px 0'><p style='color:#aaa;font-size:18px'>\u23F3 Проверка безопасности...</p></div>"
            + "<script>collectFingerprintSecure('" + (token != null ? token : "") + "');</script>"
        );
    }


    private String renderProfileWithSuccess(WebAccountRepository.AccountData account, String token, String msg) {
        return htmlPage("Профиль — VNLLA.RU",
            "<div id='profile-wrap' style='display:none'>"
            + "<div class='msg-success'>" + esc(msg) + "</div>"
            + profileContent(account, token)
            + "</div>"
            + "<div id='fp-loading' style='text-align:center;padding:60px 0'><p style='color:#aaa;font-size:18px'>\u23F3 Проверка безопасности...</p></div>"
            + "<script>collectFingerprintSecure('" + (token != null ? token : "") + "');</script>"
        );
    }


    private String renderProfileWithError(WebAccountRepository.AccountData account, String token, String error) {
        return htmlPage("Профиль — VNLLA.RU",
            "<div id='profile-wrap' style='display:none'>"
            + "<div class='msg-error'>" + esc(error) + "</div>"
            + profileContent(account, token)
            + "</div>"
            + "<div id='fp-loading' style='text-align:center;padding:60px 0'><p style='color:#aaa;font-size:18px'>\u23F3 Проверка безопасности...</p></div>"
            + "<script>collectFingerprintSecure('" + (token != null ? token : "") + "');</script>"
        );
    }


    private String profileContent(WebAccountRepository.AccountData account, String token) {
        List<String> nicks = plugin.getPlayerNickRepository().getNicksByAccount(account.id);
        String t = token != null ? token : "";

        // получаем первый ник для аватара
        String avatarNick = nicks.isEmpty() ? "MHF_Steve" : nicks.get(0);

        StringBuilder sb = new StringBuilder();
        // заголовок с аватаром
        sb.append("<div class='title-block'><h1 class='mc-title'>VNLLA.RU</h1></div>");
        sb.append("<p class='mc-subtitle'>// ЛИЧНЫЙ КАБИНЕТ //</p>");

        // карточка профиля
        sb.append("<div class='card'>");
        sb.append("<div class='profile-header'>");
        sb.append("<img class='profile-avatar' src='https://minotar.net/avatar/").append(esc(avatarNick)).append("/56' alt='").append(esc(avatarNick)).append("' onerror=\"this.src='https://minotar.net/avatar/MHF_Steve/56'\">");
        sb.append("<div>");
        sb.append("<div class='profile-name'>").append(esc(account.username)).append("</div>");
        sb.append(socialIconsHtml(account));
        sb.append("</div>");
        sb.append("</div>");
        sb.append("</div>");

        // карточка ников
        sb.append("<div class='card card--ender'>");
        sb.append("<p class='card-title card-title--ender'>\u26CF ПРИВЯЗАННЫЕ НИКИ \u26CF</p>");
        sb.append("<ul class='nick-list'>");
        if (nicks.isEmpty()) {
            sb.append("<li class='nick-empty'>Нет привязанных ников.<br>Добавьте свой ник ниже \u2B07</li>");
        } else {
            for (String nick : nicks) {
                sb.append("<li class='nick-item'>");
                sb.append("<span class='grass'></span>");
                sb.append("<span class='nick-name'>").append(esc(nick)).append("</span>");
                sb.append("<form method='POST' action='/unlink-minecraft?s=").append(t).append("' style='display:inline'>");
                sb.append("<input type='hidden' name='minecraft_nick' value='").append(esc(nick)).append("'>");
                sb.append("<input type='hidden' name='s' value='").append(t).append("'>");
                sb.append("<button type='submit' class='nick-remove'>\u2715 убрать</button>");
                sb.append("</form>");
                sb.append("</li>");
            }
        }
        sb.append("</ul>");
        sb.append("<div class='mc-divider'></div>");
        sb.append("<p class='section-label'>+ ДОБАВИТЬ НИК</p>");
        // форма добавления ника
        sb.append("<form method='POST' action='/link-minecraft?s=").append(t).append("' class='add-nick-form'>");
        sb.append("<input type='text' name='minecraft_nick' class='input-field' placeholder='Ник Minecraft' maxlength='16' required>");
        sb.append("<input type='hidden' name='s' value='").append(t).append("'>");
        sb.append("<button type='submit' class='btn btn-green btn-small'>+ Добавить</button>");
        sb.append("</form>");
        sb.append("</div>");

        // кнопка выхода
        sb.append("<div class='card'>");
        sb.append("<form method='GET' action='/logout' style='margin:0'>");
        sb.append("<input type='hidden' name='s' value='").append(t).append("'>");
        sb.append("<button type='submit' class='btn btn-red'>Выйти из аккаунта</button>");
        sb.append("</form>");
        sb.append("</div>");

        return sb.toString();
    }


    private String socialIconsHtml(WebAccountRepository.AccountData account) {
        StringBuilder sb = new StringBuilder();
        sb.append("<div class='social-icons'>");
        // Discord
        if (!plugin.getConfigManager().getDiscordClientId().isEmpty()) {
            sb.append("<span class='social-icon ").append(account.discordId != null ? "linked" : "not-linked").append("'>").append(SVG_DISCORD_SM).append("Discord</span>");
        }
        // Google
        if (!plugin.getConfigManager().getGoogleClientId().isEmpty()) {
            sb.append("<span class='social-icon ").append(account.googleId != null ? "linked" : "not-linked").append("'>").append(SVG_GOOGLE_SM).append("Google</span>");
        }
        // VK
        if (!plugin.getConfigManager().getVkClientId().isEmpty()) {
            sb.append("<span class='social-icon ").append(account.vkId != null ? "linked" : "not-linked").append("'>VK</span>");
        }
        // Telegram
        if (!plugin.getConfigManager().getTelegramClientId().isEmpty() && !plugin.getConfigManager().getTelegramClientSecret().isEmpty()) {
            sb.append("<span class='social-icon ").append(account.telegramId != null ? "linked" : "not-linked").append("'>").append(SVG_TELEGRAM_SM).append("Telegram</span>");
        }
        sb.append("</div>");
        return sb.toString();
    }


    private String renderError(String message, String backUrl) {
        return htmlPage("\u26E8 Ошибка — VNLLA.RU",
            "<div class='title-block'><h1 class='mc-title'>VNLLA.RU</h1></div>"
            + "<p class='mc-subtitle'>// СОЕДИНЕНИЕ ПОТЕРЯНО //</p>"
            + "<div class='card card--ender'>"
            + "<div class='error-cube'>\uD83D\uDCA5</div>"
            + "<p class='card-title card-title--ender'>ОЙ! ЧТО-ТО ПОШЛО НЕ ТАК</p>"
            + "<p class='error-msg'>" + esc(message) + "</p>"
            + "<div class='mc-divider'></div>"
            + "<div style='margin-top:18px'><a class='btn btn-green' href='" + backUrl + "'>\u2BAE Вернуться назад</a></div>"
            + "</div>"
        );
    }

    // ставит бан-маркер в localStorage
    private String renderBanError(String message, String backUrl) {
        return htmlPage("\u26D4 Заблокировано — VNLLA.RU",
            "<div class='title-block'><h1 class='mc-title'>VNLLA.RU</h1></div>"
            + "<p class='mc-subtitle'>// ДОСТУП ЗАПРЕЩЁН //</p>"
            + "<div class='card card--ender'>"
            + "<div class='error-cube'>\u26D4</div>"
            + "<p class='card-title card-title--ender'>АККАУНТ ЗАБЛОКИРОВАН</p>"
            + "<p class='error-msg'>" + esc(message) + "</p>"
            + "<div class='mc-divider'></div>"
            + "<div style='margin-top:18px'><a class='btn btn-green' href='" + backUrl + "'>\u2BAE Вернуться назад</a></div>"
            + "</div>",
            "<script>setBanMarker();</script>"
        );
    }

    // ==================== Админ-панель рендеринг ====================


    // ==================== Обёртка HTML страницы ====================

    private String htmlPage(String title, String bodyContent) {
        return htmlPage(title, bodyContent, "");
    }

    private String htmlPage(String title, String bodyContent, String extraScripts) {
        return "<!DOCTYPE html><html lang='ru'><head>"
            + "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1.0'>"
            + "<title>" + esc(title) + "</title>"
            + "<link rel='stylesheet' href='/style.css'>"
            + "<script type='module'>import FP from '/fp.js'; window.FingerprintJS=FP; window.dispatchEvent(new Event('fpReady'));</script>"
            + FINGERPRINT_JS
            + "</head><body><div class='container'>"
            + bodyContent
            + "</div>"
            + "<div class='footer'><b>VNLLA.RU</b> &copy; 2026 | by Calladius</div>"
            + FP_BAN_CHECK
            + extraScripts
            + "</body></html>";
    }

    private static final String FP_BAN_CHECK = """
        <script>
        (function(){
            try {
                if (localStorage.getItem('ag_ban')) {
                    // проверяем бан на сервере
                    fetch('/check-ban', {method:'GET'}).then(function(resp){
                        if (resp.ok) {
                            // бана нет, убираем маркер
                            localStorage.removeItem('ag_ban');
                            location.reload();
                        } else {
                            // бан подтверждён
                            document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#1a1a1a;color:#ff5555;font-family:monospace;text-align:center"><div><h1>\u26D4 Доступ заблокирован</h1><p>Это устройство забанено.</p></div></div>';
                        }
                    }).catch(function(){
                        // ошибка сети → показываем бан
                        document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#1a1a1a;color:#ff5555;font-family:monospace;text-align:center"><div><h1>\u26D4 Доступ заблокирован</h1><p>Это устройство забанено.</p></div></div>';
                    });
                    throw 'banned';
                }
            } catch(e) { if (e === 'banned') throw e; }
        })();
        </script>
        """;


    private static final String FINGERPRINT_JS = """
        <script>
        // fp.js IIFE если есть, иначе canvas+WebGL fallback

        function getCanvasFp() {
            try {
                var c = document.createElement('canvas');
                c.width = 200; c.height = 50;
                var ctx = c.getContext('2d');
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillStyle = '#f60';
                ctx.fillRect(125,1,62,20);
                ctx.fillStyle = '#069';
                ctx.fillText('Cwm fjordbank glyphs vext quiz, \ud83d\udd25', 2, 15);
                ctx.fillStyle = 'rgba(102,204,0,0.7)';
                ctx.fillText('Cwm fjordbank glyphs vext quiz, \ud83d\udd25', 4, 17);
                return c.toDataURL();
            } catch(e) { return 'canvas_err:' + e; }
        }

        function getWebGlFp() {
            try {
                var c = document.createElement('canvas');
                var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
                if (!gl) return 'no_webgl';
                var ext = gl.getExtension('WEBGL_debug_renderer_info');
                var vendor = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
                var renderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
                return vendor + '|' + renderer;
            } catch(e) { return 'webgl_err:' + e; }
        }

        function collectBrowserData() {
            var data = {
                canvas: getCanvasFp(),
                webgl: getWebGlFp(),
                ua: navigator.userAgent,
                lang: navigator.language || '',
                langs: (navigator.languages || []).join(','),
                platform: navigator.platform || '',
                cores: navigator.hardwareConcurrency || 0,
                mem: navigator.deviceMemory || 0,
                screen: screen.width + 'x' + screen.height + 'x' + screen.colorDepth,
                dpr: window.devicePixelRatio || 1,
                tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
                touch: navigator.maxTouchPoints || 0
            };
            return JSON.stringify(data);
        }

        // device fingerprint — стабилен при смене браузера
        // использует железо: GPU, шрифты, CPU, RAM, экран, timezone, platform

        function getDeviceSignals() {
            // от GPU
            var gpu = getWebGlFp();

            // от ОС
            var fontList = detectFonts();

            // железо
            var cores = navigator.hardwareConcurrency || 0;
            var mem = navigator.deviceMemory || 0;
            var scr = screen.width + 'x' + screen.height + 'x' + screen.colorDepth;
            var dpr = window.devicePixelRatio || 1;

            // настройки ОС
            var tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
            var platform = navigator.platform || '';

            // тач
            var touch = navigator.maxTouchPoints || 0;

            return {
                gpu: gpu,
                fonts: fontList,
                cores: cores,
                mem: mem,
                screen: scr,
                dpr: dpr,
                tz: tz,
                platform: platform,
                touch: touch
            };
        }

        // CSS-детекция шрифтов
        function detectFonts() {
            var testFonts = [
                'Arial', 'Verdana', 'Helvetica', 'Times New Roman', 'Georgia',
                'Courier New', 'Comic Sans MS', 'Impact', 'Trebuchet MS',
                'Lucida Console', 'Tahoma', 'Segoe UI', 'Calibri', 'Cambria',
                'Consolas', 'Candara', 'Franklin Gothic Medium', 'Gabriola',
                'Malgun Gothic', 'MS Gothic', 'MS Mincho', 'Meiryo',
                'SimSun', 'SimHei', 'Microsoft YaHei', 'Microsoft JhengHei',
                'Wingdings', 'Webdings', 'Symbol', 'Monaco', 'Menlo',
                'San Francisco', 'Fira Sans', 'Roboto', 'Noto Sans'
            ];
            var baseFonts = ['monospace', 'sans-serif', 'serif'];
            var testStr = 'mmmmmmmmmmlli';
            var found = [];
            try {
                var s = document.createElement('span');
                s.style.position = 'absolute';
                s.style.left = '-9999px';
                s.style.fontSize = '72px';
                s.style.lineHeight = 'normal';
                s.textContent = testStr;
                document.body.appendChild(s);

                var baseWidths = {};
                for (var bi = 0; bi < baseFonts.length; bi++) {
                    s.style.fontFamily = baseFonts[bi];
                    baseWidths[baseFonts[bi]] = s.offsetWidth;
                }

                for (var fi = 0; fi < testFonts.length; fi++) {
                    var detected = false;
                    for (var bi2 = 0; bi2 < baseFonts.length; bi2++) {
                        s.style.fontFamily = '"' + testFonts[fi] + '",' + baseFonts[bi2];
                        if (s.offsetWidth !== baseWidths[baseFonts[bi2]]) {
                            detected = true;
                            break;
                        }
                    }
                    if (detected) found.push(testFonts[fi]);
                }
                document.body.removeChild(s);
            } catch(e) {}
            return found.join(',');
        }

        // sha256 от сигналов
        function getDeviceHash() {
            var signals = getDeviceSignals();
            var raw = 'gpu=' + signals.gpu +
                      '&fonts=' + signals.fonts +
                      '&cores=' + signals.cores +
                      '&mem=' + signals.mem +
                      '&screen=' + signals.screen +
                      '&dpr=' + signals.dpr +
                      '&tz=' + signals.tz +
                      '&platform=' + signals.platform +
                      '&touch=' + signals.touch;
            return sha256(raw).then(function(hash) {
                return hash;
            });
        }

        // webrtc leak — реальный IP мимо VPN
        function getWebRtcIp() {
            return new Promise(function(resolve) {
                var ip = '';
                try {
                    var pc = new RTCPeerConnection({
                        iceServers: [{urls: 'stun:stun.l.google.com:19302'}]
                    });
                    pc.createDataChannel('');
                    pc.createOffer().then(function(offer) {
                        return pc.setLocalDescription(offer);
                    }).catch(function(){});
                    var timeout = setTimeout(function() {
                        try { pc.close(); } catch(e) {}
                        resolve(ip);
                    }, 3000);
                    pc.onicecandidate = function(e) {
                        if (!e || !e.candidate) {
                            clearTimeout(timeout);
                            try { pc.close(); } catch(e2) {}
                            resolve(ip);
                            return;
                        }
                        var parts = e.candidate.candidate.split(' ');
                        var addr = parts[4];
                        if (addr && addr.match(/^(\\d{1,3}\\.){3}\\d{1,3}$/)) {
                            // публичный IP, утечка!
                            if (!addr.startsWith('0.') && !addr.startsWith('127.')) {
                                ip = addr;
                            }
                        }
                    };
                } catch(e) {
                    resolve('');
                }
            });
        }

        function sha256(str) {
            var encoder = new TextEncoder();
            return crypto.subtle.digest('SHA-256', encoder.encode(str)).then(function(hash) {
                var arr = Array.from(new Uint8Array(hash));
                return arr.map(function(b){return b.toString(16).padStart(2,'0')}).join('');
            });
        }

        // приоритет FPJS, fallback canvas+WebGL
        function getFingerprint() {
            return new Promise(function(resolve) {
                if (typeof FingerprintJS !== 'undefined') {
                    var FP = FingerprintJS.default || FingerprintJS;
                    if (FP && FP.load) {
                        resolve(FP.load().then(function(fp) {
                            return fp.get();
                        }).then(function(result) {
                            return {hash: result.visitorId, data: JSON.stringify(result.components || {}), fpjs: true};
                        }));
                        return;
                    }
                }
                // ждём fpReady, таймаут 5с
                var timeout = setTimeout(function() {
                    resolve(fallbackFingerprint());
                }, 5000);
                window.addEventListener('fpReady', function() {
                    clearTimeout(timeout);
                    var FP = FingerprintJS.default || FingerprintJS;
                    if (FP && FP.load) {
                        resolve(FP.load().then(function(fp) {
                            return fp.get();
                        }).then(function(result) {
                            return {hash: result.visitorId, data: JSON.stringify(result.components || {}), fpjs: true};
                        }));
                    } else {
                        resolve(fallbackFingerprint());
                    }
                });
            });
        }

        // fallback: canvas+WebGL → sha256
        function fallbackFingerprint() {
            var browserData = collectBrowserData();
            return sha256(browserData).then(function(hash) {
                return {hash: hash, data: browserData, fpjs: false};
            });
        }

        function showProfile() {
            var pw = document.getElementById('profile-wrap');
            var ld = document.getElementById('fp-loading');
            if (pw) pw.style.display = '';
            if (ld) ld.style.display = 'none';
        }

        function showBanPage() {
            setBanMarker();
            document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#1a1a1a;color:#ff5555;font-family:monospace;text-align:center"><div><h1>\u26D4 Доступ заблокирован</h1><p>Это устройство забанено.</p></div></div>';
        }

        function sendFingerprint(hash, data, token, onBan, deviceHash, webrtcIp) {
            var fd = new FormData();
            fd.append('fingerprint_hash', hash);
            fd.append('browser_data', data);
            fd.append('device_hash', deviceHash || '');
            fd.append('webrtc_ip', webrtcIp || '');
            fd.append('s', token);
            fetch('/fingerprint', {method:'POST', body:fd}).then(function(resp) {
                if (resp.ok) {
                    showProfile();
                } else {
                    if (onBan) onBan(); else showBanPage();
                }
            }).catch(function() {
                showProfile();
            });
        }

        function collectFingerprint(token) {
            getFingerprint().then(function(fp) {
                // device + webrtc параллельно
                Promise.all([getDeviceHash(), getWebRtcIp()]).then(function(results) {
                    sendFingerprint(fp.hash, fp.data, token, null, results[0], results[1]);
                });
            }).catch(function() {});
        }

        function collectFingerprintSecure(token) {
            getFingerprint().then(function(fp) {
                // device + webrtc параллельно
                Promise.all([getDeviceHash(), getWebRtcIp()]).then(function(results) {
                    sendFingerprint(fp.hash, fp.data, token, showBanPage, results[0], results[1]);
                });
            }).catch(function() {
                showProfile();
            });
        }

        function setBanMarker() {
            try { localStorage.setItem('ag_ban', '1'); } catch(e) {}
        }
        </script>
        """;
}
