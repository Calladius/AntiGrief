package com.antigrief.listener;

import com.antigrief.AntiGriefPlugin;
import com.antigrief.check.GeoFilter;
import com.antigrief.check.VpnChecker;
import com.antigrief.database.repository.IpBanRepository;
import com.antigrief.database.repository.WebAccountRepository;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;

// проверка до входа на сервер
// порядок: бан по IP → бан аккаунта → белый список → vpn → гео
// ip не записывается тут, это делает JoinListener
public class PreLoginListener implements Listener {

    private final AntiGriefPlugin plugin;

    public PreLoginListener(AntiGriefPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        String nick = event.getName();
        String ip = plugin.getIpChecker().extractIp(event.getAddress().toString());

        // бан по IP — белый список НЕ обходит
        IpBanRepository.IpBan ipBan = plugin.getIpBanRepository().getActiveBan(ip);
        if (ipBan != null) {
            String banInfo = ipBan.reason != null ? ipBan.reason : "Не указана";
            if (ipBan.expiresAt != null) banInfo += " (до " + ipBan.expiresAt + ")";
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED,
                LegacyComponentSerializer.legacyAmpersand().deserialize(plugin.getConfigManager().getKickBanned(banInfo)));
            plugin.getLogger().info("[PreLogin] " + nick + " (" + ip + ") забанен по IP");
            return;
        }

        // бан аккаунта — белый список НЕ обходит
        WebAccountRepository.AccountData account = plugin.getWebAccountRepository().getAccountByNick(nick);
        if (account != null && account.isBanned) {
            String reason = account.banReason != null ? account.banReason : "Не указана";
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED,
                LegacyComponentSerializer.legacyAmpersand().deserialize(plugin.getConfigManager().getKickBanned(reason)));
            plugin.getLogger().info("[PreLogin] " + nick + " забанен");
            return;
        }

        // белый список — обход vpn/гео (но не банов)
        if (plugin.getConfigManager().isWhitelisted(nick)) {
            plugin.getLogger().info("[PreLogin] " + nick + " в WL — обход vpn/гео");
            return;
        }
        if (plugin.getConfigManager().isIpWhitelisted(ip)) {
            plugin.getLogger().info("[PreLogin] " + nick + " (" + ip + ") IP в WL — обход vpn/гео");
            return;
        }

        // проверка vpn
        if (plugin.getConfigManager().isVpnCheckEnabled()) {
            if (isLocalIp(ip)) {
                plugin.getLogger().info("[PreLogin] " + nick + " (" + ip + ") локальный IP");
                return;
            }

            VpnChecker.VpnResult vpnResult = plugin.getVpnChecker().check(ip);
            if (!vpnResult.isError && vpnResult.isVpn) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    LegacyComponentSerializer.legacyAmpersand().deserialize(plugin.getConfigManager().getKickVpn()));
                plugin.getLogger().info("[PreLogin] " + nick + " vpn (" + ip + ")");
                plugin.getDiscordNotifier().notifyVpnKick(nick, ip);
                return;
            }

            // проверка страны
            if (!vpnResult.isError && vpnResult.country != null) {
                if (!plugin.getGeoFilter().isCountryAllowed(vpnResult.country)) {
                    event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        LegacyComponentSerializer.legacyAmpersand().deserialize(plugin.getConfigManager().getKickCountry(vpnResult.country)));
                    plugin.getLogger().info("[PreLogin] " + nick + " страна " + vpnResult.country);
                    plugin.getDiscordNotifier().notifyCountryKick(nick, ip, vpnResult.country);
                    return;
                }
            }
        }

        plugin.getLogger().info("[PreLogin] " + nick + " (" + ip + ") разрешён");
    }

    private boolean isLocalIp(String ip) {
        return ip.startsWith("127.") || ip.startsWith("10.") ||
               ip.startsWith("192.168.") || ip.equals("0.0.0.0") ||
               ip.startsWith("172.16.") || ip.startsWith("172.17.") ||
               ip.startsWith("172.18.") || ip.startsWith("172.19.") ||
               ip.startsWith("172.2") || ip.startsWith("172.3") ||
               ip.equals("::1") || ip.equals("localhost");
    }
}
