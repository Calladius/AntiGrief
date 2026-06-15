package com.antigrief.listener;

import com.antigrief.AntiGriefPlugin;
import com.antigrief.check.VpnChecker;
import com.antigrief.database.repository.WebAccountRepository;
import com.antigrief.util.MessageUtil;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;

// защита от кражи ника:
// ник не привязан → заморозка
// ник привязан, ip известный → пропуск
// ник привязан, ip новый, asn совпадает → динамическая смена ip провайдера → пропуск
// ник привязан, ip новый, asn другой → возможная кража ника → заморозка
public class JoinListener implements Listener {

    private final AntiGriefPlugin plugin;

    public JoinListener(AntiGriefPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();

        // folia: если кикнули в prelogin, join может всё равно сработать
        if (!player.isOnline()) return;

        String nick = player.getName();
        String ip = plugin.getIpChecker().extractIp(player.getAddress().toString());

        autoLinkWhitelist(nick, ip);

        boolean isWhitelisted = plugin.getConfigManager().isWhitelisted(nick);
        boolean isLinked = plugin.getPlayerNickRepository().isNickLinked(nick);

        if (!isLinked) {
            // ник не привязан — морозим
            if (plugin.getConfigManager().isFreezeEnabled()) {
                plugin.getFrozenPlayers().add(nick);
                String url = plugin.getConfigManager().getExternalUrl() + "/login?nick=" + nick;
                sendFreezeMessage(player, url, "Вы заморожены! Привяжите аккаунт через сайт:");
                plugin.getLogger().info("[Join] " + nick + " заморожен — ник не привязан"
                    + (isWhitelisted ? " (WL)" : ""));
                plugin.getDiscordNotifier().notifyFrozenUnlinked(nick);
            }
            return;
        }

        // ник привязан — проверяем ip
        boolean ipKnown = plugin.getPlayerIpRepository().isIpKnownForNick(nick, ip);
        boolean hasAnyIp = plugin.getPlayerIpRepository().hasAnyIpRecord(nick);

        if (!hasAnyIp || ipKnown) {
            // ip известный или первый вход — пропуск
            plugin.getFrozenPlayers().remove(nick);
            String asn = resolveAsn(ip);
            plugin.getPlayerIpRepository().recordIp(nick, ip, asn);

            // двойная проверка бана
            WebAccountRepository.AccountData account = plugin.getWebAccountRepository().getAccountByNick(nick);
            if (account != null && account.isBanned) {
                String reason = account.banReason != null ? account.banReason : "Не указана";
                player.kick(LegacyComponentSerializer.legacyAmpersand().deserialize(plugin.getConfigManager().getKickBanned(reason)));
                return;
            }

            plugin.getLogger().info("[Join] " + nick + " привязан, ip известен (" + ip + ")"
                + (asn != null ? " asn=" + asn : "")
                + (isWhitelisted ? " (WL)" : ""));
        } else {
            // ip новый — проверяем asn (провайдер)
            String asn = resolveAsn(ip);
            boolean asnKnown = asn != null && plugin.getPlayerIpRepository().isAsnKnownForNick(nick, asn);

            if (asnKnown) {
                // asn совпадает — динамическая смена ip провайдером, не кража
                plugin.getFrozenPlayers().remove(nick);
                plugin.getPlayerIpRepository().recordIp(nick, ip, asn);

                // двойная проверка бана
                WebAccountRepository.AccountData account = plugin.getWebAccountRepository().getAccountByNick(nick);
                if (account != null && account.isBanned) {
                    String reason = account.banReason != null ? account.banReason : "Не указана";
                    player.kick(LegacyComponentSerializer.legacyAmpersand().deserialize(plugin.getConfigManager().getKickBanned(reason)));
                    return;
                }

                plugin.getLogger().info("[Join] " + nick + " привязан, ip новый (" + ip + ") но asn совпадает ("
                    + asn + ") — динамическая смена провайдера, пропуск"
                    + (isWhitelisted ? " (WL)" : ""));
            } else {
                // asn другой или неизвестен — возможная кража ника, морозим
                // белый список НЕ обходит эту проверку
                if (plugin.getConfigManager().isFreezeEnabled()) {
                    plugin.getFrozenPlayers().add(nick);
                    String url = plugin.getConfigManager().getExternalUrl() + "/login?nick=" + nick;
                    sendFreezeMessage(player, url, "Вход с нового IP! Подтвердите вход через сайт:");
                    plugin.getLogger().warning("[Join] " + nick + " заморожен — ip новый (" + ip + ")"
                        + (asn != null ? " asn=" + asn + " (новый провайдер)" : " asn неизвестен") + "!");
                    plugin.getDiscordNotifier().notifyNewIpLogin(nick, ip);
                } else {
                    plugin.getPlayerIpRepository().recordIp(nick, ip, asn);
                    plugin.getLogger().warning("[Join] " + nick + " ip новый (" + ip + ")"
                        + (asn != null ? " asn=" + asn : " asn неизвестен")
                        + ", заморозка отключена — пропуск");
                }
            }
        }
    }

    // получить asn из кеша vpnchecker (уже заполнен после prelogin)
    // если кеша нет — делаем запрос к ip-api.com
    private String resolveAsn(String ip) {
        if (isLocalIp(ip)) return null;
        try {
            VpnChecker.VpnResult result = plugin.getVpnChecker().check(ip);
            return result.asn;
        } catch (Exception e) {
            plugin.getLogger().warning("[Join] не удалось получить asn для " + ip + ": " + e.getMessage());
            return null;
        }
    }

    // если ip в wl → добавляем ник в wl
    private void autoLinkWhitelist(String nick, String ip) {
        boolean ipInWl = plugin.getConfigManager().isIpWhitelisted(ip);
        boolean nickInWl = plugin.getConfigManager().isWhitelisted(nick);

        if (ipInWl && !nickInWl) {
            plugin.getConfigManager().addWhitelistNick(nick);
            plugin.getLogger().info("[WL] авто: ip " + ip + " в WL → ник " + nick + " добавлен");
        }
        // ник в wl а ip нет — НЕ добавляем ip автоматически, это дыра в безопасности
    }

    private void sendFreezeMessage(Player player, String url, String message) {
        player.sendMessage(MessageUtil.freezeMessageWithText(url, message));
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
