package com.antigrief.command;

import com.antigrief.AntiGriefPlugin;
import com.antigrief.util.MessageUtil;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;

// /angri — основная команда плагина
public class WebCommand implements CommandExecutor, TabCompleter {

    private final AntiGriefPlugin plugin;

    public WebCommand(AntiGriefPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command,
                              @NotNull String label, @NotNull String[] args) {
        if (args.length == 0) {
            if (sender instanceof Player player) {
                String url = plugin.getConfigManager().getExternalUrl() + "/login?nick=" + player.getName();
                if (plugin.getFrozenPlayers().contains(player.getName())) {
                    player.sendMessage(MessageUtil.freezeMessage(url));
                } else {
                    player.sendMessage(MessageUtil.siteLinkMessage(url));
                }
            } else {
                sender.sendMessage("Эта команда только для игроков.");
            }
            return true;
        }

        switch (args[0].toLowerCase()) {
            case "reload" -> {
                if (!isAdmin(sender)) return true;
                plugin.getConfigManager().reload();
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&a[AntiGrief] Конфигурация перезагружена."));
                plugin.getDiscordNotifier().notifyReload(sender.getName());
            }
            case "status" -> {
                if (!isAdmin(sender)) return true;
                int onlineCount = plugin.getServer().getOnlinePlayers().size();
                int accountCount = plugin.getWebAccountRepository().getAccountCount();
                int bannedCount = plugin.getWebAccountRepository().getBannedAccountCount();
                int ipBanCount = plugin.getIpBanRepository().getAllBans().size();
                int fpBanCount = plugin.getFingerprintRepository().getAllBannedFingerprints().size();
                int deviceBanCount = plugin.getDeviceFingerprintRepository().getAllBannedDevices().size();
                String webStatus = plugin.getWebSite() != null ? "Запущен" : "Остановлен";
                List<String> wlNicks = plugin.getConfigManager().getWhitelistNicks();
                List<String> wlIps = plugin.getConfigManager().getWhitelistIps();

                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&6=== AntiGrief Status ==="));
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&fОнлайн: &a" + onlineCount + " игроков"));
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&fАккаунтов: &a" + accountCount + " &7(забанено: &c" + bannedCount + "&7)"));
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&fIP банов: &c" + ipBanCount));
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&fFingerprint банов: &c" + fpBanCount));
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&fDevice банов: &c" + deviceBanCount));
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&fВеб-сервер: &a" + webStatus));
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&fЗаморожено: &c" + plugin.getFrozenPlayers().size()));
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&fБелый список: &e" + (wlNicks.size() + wlIps.size())));
            }
            case "wl" -> handleWhitelist(sender, args);
            case "ban" -> handleBan(sender, args);
            case "unban" -> handleUnban(sender, args);
            case "banlist" -> handleBanList(sender);
            default -> sendHelp(sender);
        }
        return true;
    }

    private void sendHelp(CommandSender sender) {
        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize("&eИспользование:"));
        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
            "&f  /angri &7- ссылка на сайт"));
        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
            "&f  /angri reload &7- перезагрузить конфиг"));
        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
            "&f  /angri status &7- статус плагина"));
        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
            "&f  /angri wl add <ник/IP> &7- добавить в белый список"));
        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
            "&f  /angri wl remove <ник/IP> &7- убрать из белого списка"));
        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
            "&f  /angri wl list &7- показать белый список"));
        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
            "&f  /angri ban <IP/ник> [причина] [1h30m/7d/1y...] &7- забанить по IP"));
        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
            "&f  /angri unban <IP/ник> &7- разбанить"));
        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
            "&f  /angri banlist &7- список забаненных"));
    }

    // вайтлист: ники + ip
    private void handleWhitelist(CommandSender sender, String[] args) {
        if (!isAdmin(sender)) return;
        if (args.length < 2) {
            sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                "&eИспользование: /angri wl add/remove/list <ник/IP>"));
            return;
        }

        switch (args[1].toLowerCase()) {
            case "add" -> {
                if (args.length < 3) {
                    sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                        "&cУкажите ник или IP: /angri wl add <ник/IP>"));
                    return;
                }
                String target = args[2];
                if (isIpAddress(target)) {
                    if (plugin.getConfigManager().addWhitelistIp(target)) {
                        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                            "&a[AntiGrief] IP &e" + target + " &aдобавлен в белый список. "
                            + "&7При входе игрока с этого IP - его ник будет добавлен автоматически."));
                        plugin.getDiscordNotifier().notifyWlAdd(sender.getName(), target, "IP");
                    } else {
                        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                            "&e[AntiGrief] IP &f" + target + " &eуже в белом списке."));
                    }
                } else {
                    if (plugin.getConfigManager().addWhitelistNick(target)) {
                        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                            "&a[AntiGrief] Ник &e" + target + " &aдобавлен в белый список. "
                            + "&7При входе этого игрока - его IP будет добавлен автоматически."));
                        plugin.getDiscordNotifier().notifyWlAdd(sender.getName(), target, "ник");
                    } else {
                        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                            "&e[AntiGrief] Ник &f" + target + " &eуже в белом списке."));
                    }
                }
            }
            case "remove" -> {
                if (args.length < 3) {
                    sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                        "&cУкажите ник или IP: /angri wl remove <ник/IP>"));
                    return;
                }
                String target = args[2];
                boolean removedNick = plugin.getConfigManager().removeWhitelistNick(target);
                boolean removedIp = plugin.getConfigManager().removeWhitelistIp(target);
                if (removedNick) {
                    sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                        "&a[AntiGrief] Ник &e" + target + " &aубран из белого списка."));
                    plugin.getDiscordNotifier().notifyWlRemove(sender.getName(), target, "ник");
                } else if (removedIp) {
                    sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                        "&a[AntiGrief] IP &e" + target + " &aубран из белого списка."));
                    plugin.getDiscordNotifier().notifyWlRemove(sender.getName(), target, "IP");
                } else {
                    sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                        "&e[AntiGrief] &f" + target + " &eне найден в белом списке."));
                }
            }
            case "list" -> {
                List<String> nicks = plugin.getConfigManager().getWhitelistNicks();
                List<String> ips = plugin.getConfigManager().getWhitelistIps();
                if (nicks.isEmpty() && ips.isEmpty()) {
                    sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                        "&e[AntiGrief] Белый список пуст."));
                } else {
                    sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                        "&a[AntiGrief] Белый список:"));
                    if (!nicks.isEmpty()) {
                        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                            "&f  Ники (&e" + nicks.size() + "&f): &a" + String.join(", ", nicks)));
                    }
                    if (!ips.isEmpty()) {
                        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                            "&f  IP (&e" + ips.size() + "&f): &a" + String.join(", ", ips)));
                    }
                }
            }
            default -> sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                "&eИспользование: /angri wl add/remove/list <ник/IP>"));
        }
    }

    // ban: по ip — один ip, по нику — все его ip + аккаунт
    private void handleBan(CommandSender sender, String[] args) {
        if (!isAdmin(sender)) return;
        if (args.length < 2) {
            sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                "&eИспользование: /angri ban <IP/ник> [причина] [1h30m/7d/1y...]"));
            return;
        }
        String target = args[1];
        String reason = args.length >= 3 ? args[2] : "Не указана";
        String duration = args.length >= 4 ? args[3] : null;

        String expiresAt = null;
        if (duration != null) {
            expiresAt = parseDuration(duration);
            if (expiresAt == null) {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&c[AntiGrief] Неверный формат времени. Примеры: 30m, 1h30m, 7d, 2w3d, 1M, 1y"));
                return;
            }
        }

        String banType = expiresAt != null ? "до " + expiresAt : "перманентно";

        if (isIpAddress(target)) {
            var existingBan = plugin.getIpBanRepository().getActiveBan(target);
            if (existingBan != null) {
                String existingDuration = existingBan.expiresAt != null ? "до " + existingBan.expiresAt : "перманентно";
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&e[AntiGrief] IP &f" + target + " &eуже забанен (" + existingDuration + "). Причина: &f" + (existingBan.reason != null ? existingBan.reason : "?")));
                return;
            }
            plugin.getIpBanRepository().banIp(target, reason, sender.getName(), expiresAt);
            sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                "&a[AntiGrief] IP &e" + target + " &aзабанен (" + banType + "). Причина: &f" + reason));
            plugin.getLogger().info("[Ban] IP " + target + " забанен (" + banType + "): " + reason + " (админ: " + sender.getName() + ")");
            plugin.getDiscordNotifier().notifyBanIp(sender.getName(), target, reason, banType);
        } else {
            int accountId = plugin.getPlayerNickRepository().getAccountIdByNick(target);
            if (accountId > 0 && plugin.getWebAccountRepository().isAccountBanned(accountId)) {
                var account = plugin.getWebAccountRepository().getAccount(accountId);
                String existingDuration = account != null && account.banExpires != null ? "до " + account.banExpires : "перманентно";
                String existingReason = account != null && account.banReason != null ? account.banReason : "?";
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&e[AntiGrief] Ник &f" + target + " &eуже забанен (" + existingDuration + "). Причина: &f" + existingReason));
                return;
            }

            var ipRecords = plugin.getPlayerIpRepository().getIpsByNick(target);
            int banned = 0;
            for (var record : ipRecords) {
                if (plugin.getIpBanRepository().banIp(record.ipAddress, reason + " (ник: " + target + ")", sender.getName(), expiresAt)) {
                    banned++;
                }
            }

            // бан аккаунта на сайте
            boolean accountBanned = false;
            if (accountId > 0) {
                plugin.getWebAccountRepository().banAccount(accountId, reason, expiresAt);
                accountBanned = true;
            }

            if (banned > 0 || accountId > 0) {
                String msg = "&a[AntiGrief] &e" + target + " &aзабанен";
                msg += " &7(Срок: &f" + banType + "&7)";
                msg += " &7(Причина: &f" + reason + "&7)";
                if (banned > 0) msg += " &7(IP: &f" + banned + "&7)";
                if (accountBanned) msg += " &7(Сайт: забанен&7)";
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(msg));
            }
            if (banned == 0 && accountId <= 0) {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&c[AntiGrief] У ника &f" + target + " &cнет записей IP и аккаунта. Игрок ещё не заходил на сервер."));
            }
            plugin.getLogger().info("[Ban] " + banned + " IP ника " + target + " забанены (" + banType + "): " + reason + " (админ: " + sender.getName() + ")");
            plugin.getDiscordNotifier().notifyBanNick(sender.getName(), target, banned, reason, banType, accountBanned);
        }
    }

    // unban: по нику — снимает все ip-баны + аккаунт + fingerprint + device
    private void handleUnban(CommandSender sender, String[] args) {
        if (!isAdmin(sender)) return;
        if (args.length < 2) {
            sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                "&eИспользование: /angri unban <IP/ник>"));
            return;
        }
        String target = args[1];

        if (isIpAddress(target)) {
            if (plugin.getIpBanRepository().unbanIp(target)) {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&a[AntiGrief] IP &e" + target + " &aразбанен."));
                plugin.getLogger().info("[Unban] IP " + target + " разбанен (админ: " + sender.getName() + ")");
                plugin.getDiscordNotifier().notifyUnbanIp(sender.getName(), target);
            } else {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&e[AntiGrief] IP &f" + target + " &eне найден в списке банов."));
            }
        } else {
            var ipRecords = plugin.getPlayerIpRepository().getIpsByNick(target);
            int unbanned = 0;
            for (var record : ipRecords) {
                if (plugin.getIpBanRepository().unbanIp(record.ipAddress)) {
                    unbanned++;
                }
            }

            boolean accountUnbanned = false;
            int fpUnbanned = 0;
            int deviceUnbanned = 0;
            int linkedUnbanned = 0;
            int accountId = plugin.getPlayerNickRepository().getAccountIdByNick(target);
            if (accountId > 0) {
                plugin.getWebAccountRepository().unbanAccount(accountId);
                accountUnbanned = true;

                var fps = plugin.getFingerprintRepository().getFingerprintsByAccount(accountId);
                for (var fp : fps) {
                    if (plugin.getFingerprintRepository().unbanFingerprint(fp.fingerprintHash)) {
                        fpUnbanned++;
                    }
                    // разбан аккаунтов с этим fp
                    var linkedIds = plugin.getFingerprintRepository().getAccountsByFingerprint(fp.fingerprintHash);
                    for (int aid : linkedIds) {
                        if (aid != accountId && plugin.getWebAccountRepository().isAccountBanned(aid)) {
                            plugin.getWebAccountRepository().unbanAccount(aid);
                            linkedUnbanned++;
                        }
                    }
                }

                var deviceFps = plugin.getDeviceFingerprintRepository().getDeviceFingerprintsByAccount(accountId);
                for (var dfp : deviceFps) {
                    if (plugin.getDeviceFingerprintRepository().unbanDevice(dfp.deviceHash)) {
                        deviceUnbanned++;
                    }
                    // разбан аккаунтов с этим device
                    var linkedIds = plugin.getDeviceFingerprintRepository().getAccountsByDevice(dfp.deviceHash);
                    for (int aid : linkedIds) {
                        if (aid != accountId && plugin.getWebAccountRepository().isAccountBanned(aid)) {
                            plugin.getWebAccountRepository().unbanAccount(aid);
                            linkedUnbanned++;
                        }
                    }
                }
            }

            if (unbanned > 0 || accountId > 0) {
                String msg = "&a[AntiGrief] Ник &e" + target + " &aразбанен";
                msg += " &7(IP: &f" + unbanned + "&7)";
                if (accountUnbanned) msg += " &7(аккаунт)&7";
                if (fpUnbanned > 0) msg += " &7(FP: &f" + fpUnbanned + "&7)";
                if (deviceUnbanned > 0) msg += " &7(Device: &f" + deviceUnbanned + "&7)";
                if (linkedUnbanned > 0) msg += " &7(связанных: &f" + linkedUnbanned + "&7)";
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(msg));
                plugin.getLogger().info("[Unban] " + target + " разбанен (" + unbanned + " IP + аккаунт + " + fpUnbanned + " FP + " + deviceUnbanned + " device + " + linkedUnbanned + " связанных, админ: " + sender.getName() + ")");
                plugin.getDiscordNotifier().notifyUnbanNick(sender.getName(), target, unbanned, accountUnbanned);
            } else {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "&c[AntiGrief] У ника &f" + target + " &cнет банов."));
            }
        }
    }

    private void handleBanList(CommandSender sender) {
        if (!isAdmin(sender)) return;

        var bannedAccounts = plugin.getWebAccountRepository().getBannedAccounts();
        var ipBans = plugin.getIpBanRepository().getAllBans();

        if (bannedAccounts.isEmpty() && ipBans.isEmpty()) {
            sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                "&a[AntiGrief] Нет забаненных аккаунтов и IP."));
            return;
        }

        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
            "&6=== Список банов ==="));

        if (!bannedAccounts.isEmpty()) {
            sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                "&eЗабаненные аккаунты (&c" + bannedAccounts.size() + "&e):"));
            for (var acc : bannedAccounts) {
                String nick = acc.nicks != null ? acc.nicks : acc.username;
                String duration = acc.banExpires != null ? "до " + acc.banExpires : "&cперманентно";
                String reason = acc.banReason != null ? acc.banReason : "?";
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "  &f" + nick + " &7(" + duration + "&7) &8- " + reason));
            }
        }

        // только ip-баны без привязки к аккаунту
        if (!ipBans.isEmpty()) {
            sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                "&eIP баны (&c" + ipBans.size() + "&e):"));
            for (var ban : ipBans) {
                String duration = ban.expiresAt != null ? "до " + ban.expiresAt : "&cперманентно";
                String reason = ban.reason != null ? ban.reason : "?";
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(
                    "  &f" + ban.ipAddress + " &7(" + duration + "&7) &8- " + reason));
            }
        }
    }

    private boolean isIpAddress(String s) {
        if (s.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) return true;
        if (s.contains(":")) return true;
        return false;
    }

    // проверка прав + отправка сообщения об ошибке
    private boolean isAdmin(CommandSender sender) {
        if (!sender.hasPermission("antigrief.admin")) {
            String msg = plugin.getConfigManager().getGameNoPermission();
            sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(msg));
            return false;
        }
        return true;
    }

    // формат: 1y2mo3w4d5h6m7s — любая комбинация без повторов единиц
    private String parseDuration(String duration) {
        try {
            long millis = 0;
            java.util.Set<String> usedUnits = new java.util.HashSet<>();
            java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("(\\d+)([smhdwMy])").matcher(duration);
            int matchedLength = 0;
            while (matcher.find()) {
                long value = Long.parseLong(matcher.group(1));
                String unit = matcher.group(2);
                matchedLength += matcher.group(0).length();
                if (!usedUnits.add(unit)) {
                    return null;
                }
                switch (unit) {
                    case "s" -> millis += value * 1000L;
                    case "m" -> millis += value * 60000L;
                    case "h" -> millis += value * 3600000L;
                    case "d" -> millis += value * 86400000L;
                    case "w" -> millis += value * 604800000L;
                    case "M" -> millis += value * 2592000000L;
                    case "y" -> millis += value * 31536000000L;
                }
            }
            if (matchedLength != duration.length() || millis <= 0) return null;

            java.time.Instant expires = java.time.Instant.ofEpochMilli(System.currentTimeMillis() + millis);
            return expires.toString().substring(0, 19).replace("T", " ");
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @Override
    public @Nullable List<String> onTabComplete(@NotNull CommandSender sender, @NotNull Command cmd,
                                                 @NotNull String alias, @NotNull String[] args) {
        List<String> completions = new ArrayList<>();

        if (args.length == 1) {
            List<String> subs = List.of("reload", "status", "wl", "ban", "unban", "banlist");
            for (String s : subs) {
                if (s.startsWith(args[0].toLowerCase())) completions.add(s);
            }
        } else if (args.length == 2 && args[0].equalsIgnoreCase("wl")) {
            List<String> actions = List.of("add", "remove", "list");
            for (String a : actions) {
                if (a.startsWith(args[1].toLowerCase())) completions.add(a);
            }
        } else if (args.length == 3 && args[0].equalsIgnoreCase("wl") && args[1].equalsIgnoreCase("remove")) {
            completions.addAll(plugin.getConfigManager().getWhitelistNicks());
            completions.addAll(plugin.getConfigManager().getWhitelistIps());
        } else if (args.length == 2 && args[0].equalsIgnoreCase("ban")) {
            completions.addAll(plugin.getPlayerNickRepository().getUnbannedNicks());
            completions.removeIf(c -> !c.toLowerCase().startsWith(args[1].toLowerCase()));
        } else if (args.length == 2 && args[0].equalsIgnoreCase("unban")) {
            completions.addAll(plugin.getPlayerNickRepository().getBannedNicks());
            completions.removeIf(c -> !c.toLowerCase().startsWith(args[1].toLowerCase()));
        }

        return completions;
    }
}
