package com.antigrief.discord;

import com.antigrief.AntiGriefPlugin;
import net.dv8tion.jda.api.JDA;
import net.dv8tion.jda.api.JDABuilder;
import net.dv8tion.jda.api.entities.Activity;
import net.dv8tion.jda.api.requests.GatewayIntent;
import net.dv8tion.jda.api.utils.cache.CacheFlag;
import okhttp3.OkHttpClient;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;

// бот для уведомлений, подключается через socks5 (дс заблокирован в рф)
public class DiscordBot {

    private final AntiGriefPlugin plugin;
    private final String token;
    private JDA jda;

    public DiscordBot(AntiGriefPlugin plugin, String token) {
        this.plugin = plugin;
        this.token = token;
    }

    public void start() throws Exception {
        String proxyHost = plugin.getConfigManager().getProxyHost();
        int proxyPort = plugin.getConfigManager().getProxyPort();
        boolean useProxy = proxyHost != null && !proxyHost.isEmpty() && proxyPort > 0;

        // socks5 для websocket (neovisionaries не использует okhttp)
        if (useProxy) {
            System.setProperty("socksProxyHost", proxyHost);
            System.setProperty("socksProxyPort", String.valueOf(proxyPort));
            System.setProperty("socksNonProxyHosts", "localhost|127.0.0.1|0.0.0.0");
            plugin.getLogger().info("Discord бот через SOCKS5: " + proxyHost + ":" + proxyPort);
        }

        OkHttpClient.Builder httpClientBuilder = new OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS);

        // okhttp тоже через прокси
        if (useProxy) {
            httpClientBuilder.proxy(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(proxyHost, proxyPort)));
        }

        jda = JDABuilder.createDefault(token)
            .setEnabledIntents(GatewayIntent.GUILD_MESSAGES, GatewayIntent.MESSAGE_CONTENT)
            .disableCache(EnumSet.allOf(CacheFlag.class))
            .setActivity(Activity.playing("AntiGrief"))
            .setHttpClient(httpClientBuilder.build())
            .build();
        jda.awaitReady();

        plugin.getLogger().info("Discord бот подключён! Серверы: " + jda.getGuilds().size());
    }

    public void stop() {
        if (jda != null) jda.shutdown();
        System.clearProperty("socksProxyHost");
        System.clearProperty("socksProxyPort");
        System.clearProperty("socksNonProxyHosts");
    }

    public JDA getJda() { return jda; }
}
