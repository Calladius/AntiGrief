package com.antigrief.config;

import com.antigrief.AntiGriefPlugin;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

// конфиги + сообщения
public class ConfigManager {

    private final AntiGriefPlugin plugin;
    private FileConfiguration config;
    private FileConfiguration messages;

    public ConfigManager(AntiGriefPlugin plugin) {
        this.plugin = plugin;
    }

    public void load() {
        plugin.reloadConfig();
        config = plugin.getConfig();

        File messagesFile = new File(plugin.getDataFolder(), "messages_ru.yml");
        messages = YamlConfiguration.loadConfiguration(messagesFile);
    }

    public void reload() {
        load();
    }

    // база данных

    public String getDatabaseFile() {
        return config.getString("database.file", "data.db");
    }

    public int getDatabasePoolSize() {
        return config.getInt("database.pool-size", 5);
    }

    // веб

    public int getWebsitePort() {
        return config.getInt("website.port", 8199);
    }

    public String getExternalUrl() {
        return config.getString("website.external-url", "https://mc.vnlla.ru");
    }

    // прокси

    public String getProxyHost() {
        return config.getString("proxy.host", "");
    }

    public int getProxyPort() {
        return config.getInt("proxy.port", 0);
    }

    // discord

    public String getDiscordClientId() {
        return config.getString("discord.client-id", "");
    }

    public String getDiscordClientSecret() {
        return config.getString("discord.client-secret", "");
    }

    public String getDiscordBotToken() {
        return config.getString("discord.bot-token", "");
    }

    public String getDiscordNotifyChannelId() {
        return config.getString("discord.notify-channel-id", "");
    }

    // google

    public String getGoogleClientId() {
        return config.getString("google.client-id", "");
    }

    public String getGoogleClientSecret() {
        return config.getString("google.client-secret", "");
    }

    // vk

    public String getVkClientId() {
        return config.getString("vk.client-id", "");
    }

    public String getVkClientSecret() {
        return config.getString("vk.client-secret", "");
    }

    // telegram

    public String getTelegramBotToken() {
        return config.getString("telegram.bot-token", "");
    }

    public String getTelegramBotUsername() {
        return config.getString("telegram.bot-username", "");
    }

    public String getTelegramClientId() {
        return config.getString("telegram.client-id", "");
    }

    public String getTelegramClientSecret() {
        return config.getString("telegram.client-secret", "");
    }

    // гео

    public List<String> getAllowedCountries() {
        List<String> countries = config.getStringList("geo.allowed-countries");
        if (countries.isEmpty()) {
            return List.of("RU", "UA", "BY", "KZ", "AM", "AZ", "GE", "KG", "MD", "TJ", "TM", "UZ");
        }
        return countries;
    }

    // vpn

    public boolean isVpnCheckEnabled() {
        return config.getBoolean("vpn.enabled", true);
    }

    public String getIphubApiKey() {
        return config.getString("vpn.iphub-api-key", "");
    }

    public String getProxycheckApiKey() {
        return config.getString("vpn.proxycheck-api-key", "");
    }

    // fingerprint

    public boolean isFingerprintEnabled() {
        return config.getBoolean("fingerprint.enabled", true);
    }

    public int getMaxAccountsPerFingerprint() {
        return config.getInt("fingerprint.max-accounts-per-fingerprint", 3);
    }

    public boolean isAutoBanOnFingerprintLimit() {
        return config.getBoolean("fingerprint.auto-ban-on-limit", false);
    }

    // сессии

    public int getSessionMaxAge() {
        return config.getInt("session.max-age", 604800);
    }

    public int getNickCookieMaxAge() {
        return config.getInt("session.nick-cookie-max-age", 600);
    }

    // вайтлист

    public List<String> getWhitelistNicks() {
        return config.getStringList("whitelist.nicks");
    }

    public boolean isWhitelisted(String nick) {
        return getWhitelistNicks().stream()
            .anyMatch(n -> n.equalsIgnoreCase(nick));
    }

    // ip-вайтлист — обход vpn/гео
    public List<String> getWhitelistIps() {
        return config.getStringList("whitelist.ips");
    }

    public boolean isIpWhitelisted(String ip) {
        return getWhitelistIps().stream()
            .anyMatch(w -> w.equalsIgnoreCase(ip));
    }

    // сохраняет в config.yml
    public boolean addWhitelistNick(String nick) {
        List<String> nicks = new ArrayList<>(getWhitelistNicks());
        if (nicks.stream().anyMatch(n -> n.equalsIgnoreCase(nick))) return false;
        nicks.add(nick);
        config.set("whitelist.nicks", nicks);
        plugin.saveConfig();
        return true;
    }

    public boolean removeWhitelistNick(String nick) {
        List<String> nicks = new ArrayList<>(getWhitelistNicks());
        boolean removed = nicks.removeIf(n -> n.equalsIgnoreCase(nick));
        if (removed) {
            config.set("whitelist.nicks", nicks);
            plugin.saveConfig();
        }
        return removed;
    }

    public boolean addWhitelistIp(String ip) {
        List<String> ips = new ArrayList<>(getWhitelistIps());
        if (ips.stream().anyMatch(i -> i.equalsIgnoreCase(ip))) return false;
        ips.add(ip);
        config.set("whitelist.ips", ips);
        plugin.saveConfig();
        return true;
    }

    public boolean removeWhitelistIp(String ip) {
        List<String> ips = new ArrayList<>(getWhitelistIps());
        boolean removed = ips.removeIf(i -> i.equalsIgnoreCase(ip));
        if (removed) {
            config.set("whitelist.ips", ips);
            plugin.saveConfig();
        }
        return removed;
    }

    // заморозка

    public boolean isFreezeEnabled() {
        return config.getBoolean("freeze.enabled", true);
    }

    public String getFreezeMessage() {
        return config.getString("freeze.message", "&eПривяжи аккаунт! &f/angri");
    }

    // сообщения

    public String getPrefix() {
        return messages.getString("prefix", "&8[&6AntiGrief&8] &f");
    }

    public String getKickCountry(String country) {
        return messages.getString("kick.country", "&cДоступ только для стран СНГ. &fВаш регион: &e%country%")
            .replace("%country%", country != null ? country : "???");
    }

    public String getKickVpn() {
        return messages.getString("kick.vpn", "&cИспользование VPN/прокси запрещено.");
    }

    public String getKickBanned(String reason) {
        return messages.getString("kick.banned", "&cВы забанены. &fПричина: &e%reason%")
            .replace("%reason%", reason != null ? reason : "Не указана");
    }

    public String getKickFingerprintBanned(String reason) {
        return messages.getString("kick.fingerprint-banned", "&cВаше устройство забанено. &fПричина: &e%reason%")
            .replace("%reason%", reason != null ? reason : "Не указана");
    }

    public String getFreezeMessageFormatted() {
        String url = getExternalUrl() + "/login";
        return getFreezeMessage().replace("%url%", url);
    }

    public String getGameLinkSuccess() {
        return messages.getString("game.link-success", "&aАккаунт успешно привязан!");
    }

    public String getGameUnlinkSuccess() {
        return messages.getString("game.unlink-success", "&aНик отвязан от аккаунта.");
    }

    public String getGameAlreadyLinked() {
        return messages.getString("game.already-linked", "&eЭтот ник уже привязан к другому аккаунту.");
    }

    public String getGameNoPermission() {
        return messages.getString("game.no-permission", "&cУ вас нет прав на эту команду.");
    }

    public String getGameConfigReloaded() {
        return messages.getString("game.config-reloaded", "&aКонфигурация перезагружена.");
    }

    public String getGameWebUrl() {
        String url = getExternalUrl() + "/login";
        return messages.getString("game.web-url", "&eПривяжите аккаунт: &a%url%")
            .replace("%url%", url);
    }
}
