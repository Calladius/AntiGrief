package com.antigrief.listener;

import com.antigrief.AntiGriefPlugin;
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
// ник привязан, ip новый → заморозка (подтверди через сайт)
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
            plugin.getPlayerIpRepository().recordIp(nick, ip);

            // двойная проверка бана
            WebAccountRepository.AccountData account = plugin.getWebAccountRepository().getAccountByNick(nick);
            if (account != null && account.isBanned) {
                String reason = account.banReason != null ? account.banReason : "Не указана";
                player.kick(LegacyComponentSerializer.legacyAmpersand().deserialize(plugin.getConfigManager().getKickBanned(reason)));
                return;
            }

            plugin.getLogger().info("[Join] " + nick + " привязан, ip известен (" + ip + ")"
                + (isWhitelisted ? " (WL)" : ""));
        } else {
            // ip новый — возможная кража ника, морозим
            // белый список НЕ обходит эту проверку
            if (plugin.getConfigManager().isFreezeEnabled()) {
                plugin.getFrozenPlayers().add(nick);
                String url = plugin.getConfigManager().getExternalUrl() + "/login?nick=" + nick;
                sendFreezeMessage(player, url, "Вход с нового IP! Подтвердите вход через сайт:");
                plugin.getLogger().warning("[Join] " + nick + " заморожен — ip новый (" + ip + ")!");
                plugin.getDiscordNotifier().notifyNewIpLogin(nick, ip);
            } else {
                plugin.getPlayerIpRepository().recordIp(nick, ip);
                plugin.getLogger().warning("[Join] " + nick + " ip новый (" + ip + "), заморозка отключена — пропуск");
            }
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
}
