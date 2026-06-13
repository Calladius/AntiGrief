package com.antigrief;

import com.antigrief.check.GeoFilter;
import com.antigrief.check.IpChecker;
import com.antigrief.check.VpnChecker;
import com.antigrief.command.WebCommand;
import com.antigrief.config.ConfigManager;
import com.antigrief.database.DatabaseManager;
import com.antigrief.database.repository.DeviceFingerprintRepository;
import com.antigrief.database.repository.FingerprintRepository;
import com.antigrief.database.repository.IpBanRepository;
import com.antigrief.database.repository.PlayerIpRepository;
import com.antigrief.database.repository.PlayerNickRepository;
import com.antigrief.database.repository.WebAccountRepository;
import com.antigrief.discord.DiscordBot;
import com.antigrief.discord.DiscordNotifier;
import com.antigrief.listener.ChatListener;
import com.antigrief.listener.CommandListener;
import com.antigrief.listener.JoinListener;
import com.antigrief.listener.MoveListener;
import com.antigrief.listener.PreLoginListener;
import com.antigrief.listener.QuitListener;
import com.antigrief.listener.FreezeListener;
import com.antigrief.util.MessageUtil;
import com.antigrief.web.SessionManager;
import com.antigrief.web.WebSite;
import org.bukkit.plugin.java.JavaPlugin;

public class AntiGriefPlugin extends JavaPlugin {

    private DatabaseManager databaseManager;
    private WebAccountRepository webAccountRepository;
    private PlayerNickRepository playerNickRepository;
    private PlayerIpRepository playerIpRepository;
    private FingerprintRepository fingerprintRepository;
    private DeviceFingerprintRepository deviceFingerprintRepository;
    private IpBanRepository ipBanRepository;
    private ConfigManager configManager;
    private SessionManager sessionManager;
    private IpChecker ipChecker;
    private VpnChecker vpnChecker;
    private GeoFilter geoFilter;
    private WebSite webSite;
    private DiscordBot discordBot;
    private DiscordNotifier discordNotifier;
    private final java.util.Set<String> frozenPlayers = java.util.concurrent.ConcurrentHashMap.newKeySet();

    @Override
    public void onEnable() {
        saveDefaultConfig();
        saveResource("messages_ru.yml", false);

        configManager = new ConfigManager(this);
        configManager.load();
        MessageUtil.init(configManager);

        // бд
        databaseManager = new DatabaseManager(getDataFolder());
        try {
            databaseManager.connect();
            getLogger().info("БД подключена");
        } catch (Exception e) {
            getLogger().severe("Ошибка БД: " + e.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        webAccountRepository = new WebAccountRepository(databaseManager);
        playerNickRepository = new PlayerNickRepository(databaseManager);
        playerIpRepository = new PlayerIpRepository(databaseManager);
        fingerprintRepository = new FingerprintRepository(databaseManager);
        deviceFingerprintRepository = new DeviceFingerprintRepository(databaseManager);
        ipBanRepository = new IpBanRepository(databaseManager);
        sessionManager = new SessionManager(configManager, webAccountRepository);

        ipChecker = new IpChecker();
        vpnChecker = new VpnChecker(configManager, this);
        geoFilter = new GeoFilter(configManager);

        // discord
        discordNotifier = new DiscordNotifier(this);
        String botToken = configManager.getDiscordBotToken();
        if (botToken != null && !botToken.isEmpty()) {
            discordBot = new DiscordBot(this, botToken);
            try {
                discordBot.start();
            } catch (Exception e) {
                getLogger().warning("Discord бот не запустился: " + e.getMessage());
            }
        }

        // веб
        webSite = new WebSite(this);
        try {
            webSite.start();
            getLogger().info("Веб на порту " + configManager.getWebsitePort());
        } catch (Exception e) {
            getLogger().severe("Ошибка веб-сервера: " + e.getMessage());
        }

        // слушатели
        getServer().getPluginManager().registerEvents(new PreLoginListener(this), this);
        getServer().getPluginManager().registerEvents(new JoinListener(this), this);
        getServer().getPluginManager().registerEvents(new MoveListener(this), this);
        getServer().getPluginManager().registerEvents(new ChatListener(this), this);
        getServer().getPluginManager().registerEvents(new CommandListener(this), this);
        getServer().getPluginManager().registerEvents(new QuitListener(this), this);
        getServer().getPluginManager().registerEvents(new FreezeListener(this), this);

        // команда
        if (getCommand("angri") != null) {
            WebCommand webCmd = new WebCommand(this);
            getCommand("angri").setExecutor(webCmd);
            getCommand("angri").setTabCompleter(webCmd);
        }

        // чистим протухшие сессии каждые 30 мин
        getServer().getGlobalRegionScheduler().runAtFixedRate(this, task -> {
            cleanupExpiredSessions();
        }, 30 * 60 * 20L, 30 * 60 * 20L);

        getLogger().info("AntiGrief v" + getDescription().getVersion() + " включён!");
    }

    @Override
    public void onDisable() {
        if (webSite != null) webSite.stop();
        if (discordBot != null) discordBot.stop();
        if (databaseManager != null) databaseManager.disconnect();
        frozenPlayers.clear();
        getLogger().info("AntiGrief выключен");
    }

    private void cleanupExpiredSessions() {
        try (var conn = databaseManager.getConnection();
             var ps = conn.prepareStatement("DELETE FROM web_sessions WHERE expires_at <= datetime('now')")) {
            int deleted = ps.executeUpdate();
            if (deleted > 0) getLogger().info("Удалено " + deleted + " истёкших сессий");
        } catch (Exception e) {
            getLogger().warning("Ошибка очистки сессий: " + e.getMessage());
        }
    }

    public DatabaseManager getDatabaseManager() { return databaseManager; }
    public WebAccountRepository getWebAccountRepository() { return webAccountRepository; }
    public PlayerNickRepository getPlayerNickRepository() { return playerNickRepository; }
    public PlayerIpRepository getPlayerIpRepository() { return playerIpRepository; }
    public FingerprintRepository getFingerprintRepository() { return fingerprintRepository; }
    public DeviceFingerprintRepository getDeviceFingerprintRepository() { return deviceFingerprintRepository; }
    public IpBanRepository getIpBanRepository() { return ipBanRepository; }
    public ConfigManager getConfigManager() { return configManager; }
    public SessionManager getSessionManager() { return sessionManager; }
    public IpChecker getIpChecker() { return ipChecker; }
    public VpnChecker getVpnChecker() { return vpnChecker; }
    public GeoFilter getGeoFilter() { return geoFilter; }
    public WebSite getWebSite() { return webSite; }
    public DiscordBot getDiscordBot() { return discordBot; }
    public DiscordNotifier getDiscordNotifier() { return discordNotifier; }
    public java.util.Set<String> getFrozenPlayers() { return frozenPlayers; }
}
