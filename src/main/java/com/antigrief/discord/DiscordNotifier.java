package com.antigrief.discord;

import com.antigrief.AntiGriefPlugin;
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

// уведомления в discord канал, всё безопасно если бот не запущен
public class DiscordNotifier {

    private final AntiGriefPlugin plugin;
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss");

    public DiscordNotifier(AntiGriefPlugin plugin) {
        this.plugin = plugin;
    }

    private String now() { return LocalDateTime.now().format(TIME_FMT); }

    private void sendMessage(String message) {
        String channelId = plugin.getConfigManager().getDiscordNotifyChannelId();
        if (channelId == null || channelId.isEmpty()) return;

        DiscordBot bot = plugin.getDiscordBot();
        if (bot == null || bot.getJda() == null) return;

        try {
            TextChannel channel = bot.getJda().getTextChannelById(channelId);
            if (channel != null) channel.sendMessage(message).queue();
        } catch (Exception e) {
            plugin.getLogger().warning("Ошибка Discord: " + e.getMessage());
        }
    }

    // автоматические события

    public void notifyVpnKick(String nick, String ip) {
        sendMessage(":shield: **VPN/Прокси кик** | " + now() + "\nИгрок: **" + nick + "** | IP: `" + ip + "`");
    }

    public void notifyCountryKick(String nick, String ip, String country) {
        sendMessage(":globe_with_meridians: **Гео-кик** | " + now() + "\nИгрок: **" + nick + "** | IP: `" + ip + "` | Страна: " + country);
    }

    public void notifyAccountLinked(String minecraftNick, String webUsername) {
        sendMessage(":link: **Аккаунт привязан** | " + now() + "\nНик: **" + minecraftNick + "** → Веб: " + webUsername);
    }

    public void notifyNickLinked(String minecraftNick, String webUsername) {
        sendMessage(":white_check_mark: **Ник привязан** | " + now() + "\nНик: **" + minecraftNick + "** → Аккаунт: " + webUsername);
    }

    public void notifyMultiAccount(String fingerprintHash, int accountCount) {
        sendMessage(":warning: **Мульти-аккаунт** | " + now() + "\nОтпечаток: `" + fingerprintHash.substring(0, 12) + "...` | Аккаунтов: " + accountCount);
    }

    public void notifyNewIpLogin(String nick, String ip) {
        sendMessage(":rotating_light: **Новый IP — заморозка** | " + now() + "\nНик: **" + nick + "** | IP: `" + ip + "`");
    }

    public void notifyFrozenUnlinked(String nick) {
        sendMessage(":snowflake: **Заморозка — ник не привязан** | " + now() + "\nНик: **" + nick + "**");
    }

    public void notifyUnfrozen(String nick, String reason) {
        sendMessage(":fire: **Разморозка** | " + now() + "\nНик: **" + nick + "** | Причина: " + reason);
    }

    // действия админов

    public void notifyWlAdd(String admin, String target, String type) {
        sendMessage(":notebook_with_decorative_cover: **WL +** | " + now() + "\nАдмин: **" + admin + "** | " + type + ": `" + target + "`");
    }

    public void notifyWlRemove(String admin, String target, String type) {
        sendMessage(":wastebasket: **WL -** | " + now() + "\nАдмин: **" + admin + "** | " + type + ": `" + target + "`");
    }

    public void notifyBanIp(String admin, String ip, String reason, String duration) {
        sendMessage(":hammer: **Бан IP** | " + now() + "\nАдмин: **" + admin + "** | IP: `" + ip + "`\nПричина: " + reason + " | Срок: " + duration);
    }

    public void notifyBanNick(String admin, String nick, int ipCount, String reason, String duration, boolean accountBanned) {
        StringBuilder details = new StringBuilder();
        details.append("IP: ").append(ipCount);
        if (accountBanned) details.append(" | сайт забанен");
        sendMessage(":hammer: **Бан ника** | " + now() + "\nАдмин: **" + admin + "** | Ник: **" + nick + "**\nПричина: " + reason + " | Срок: " + duration + " | " + details);
    }

    public void notifyUnbanIp(String admin, String ip) {
        sendMessage(":unlock: **Разбан IP** | " + now() + "\nАдмин: **" + admin + "** | IP: `" + ip + "`");
    }

    public void notifyUnbanNick(String admin, String nick, int ipCount, boolean accountUnbanned) {
        StringBuilder details = new StringBuilder();
        details.append("IP: ").append(ipCount);
        if (accountUnbanned) details.append(" | сайт разбанен");
        sendMessage(":unlock: **Разбан ника** | " + now() + "\nАдмин: **" + admin + "** | Ник: **" + nick + "** | " + details);
    }

    public void notifyReload(String admin) {
        sendMessage(":arrows_counterclockwise: **Конфиг перезагружен** | " + now() + "\nАдмин: **" + admin + "**");
    }

    // бан/разбан на discord сервере (пока не используется, но может понадобиться)

    public void discordBan(String discordId, String reason) {
        DiscordBot bot = plugin.getDiscordBot();
        if (bot == null || bot.getJda() == null) return;
        if (discordId == null || discordId.isEmpty()) return;

        try {
            for (var guild : bot.getJda().getGuilds()) {
                var member = guild.getMemberById(discordId);
                if (member != null) {
                    guild.ban(member, 0, java.util.concurrent.TimeUnit.SECONDS)
                        .reason("MC бан: " + (reason != null ? reason : "Не указана"))
                        .queue(
                            success -> plugin.getLogger().info("[Discord] " + discordId + " забанен на " + guild.getName()),
                            error -> plugin.getLogger().warning("[Discord] не удалось забанить " + discordId + ": " + error.getMessage())
                        );
                }
            }
        } catch (Exception e) {
            plugin.getLogger().warning("[Discord] ошибка бана " + discordId + ": " + e.getMessage());
        }
    }

    public void discordUnban(String discordId) {
        DiscordBot bot = plugin.getDiscordBot();
        if (bot == null || bot.getJda() == null) return;
        if (discordId == null || discordId.isEmpty()) return;

        try {
            for (var guild : bot.getJda().getGuilds()) {
                guild.unban(net.dv8tion.jda.api.entities.UserSnowflake.fromId(discordId))
                    .reason("MC разбан")
                    .queue(success -> {}, error -> {});
            }
        } catch (Exception e) {
            plugin.getLogger().warning("[Discord] ошибка разбана " + discordId + ": " + e.getMessage());
        }
    }
}
