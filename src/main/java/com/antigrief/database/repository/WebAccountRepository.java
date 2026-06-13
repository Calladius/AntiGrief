package com.antigrief.database.repository;

import com.antigrief.database.DatabaseManager;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

// веб-аккаунты и сессии, oauth2 рега, password_hash может быть null

public class WebAccountRepository {

    private final DatabaseManager db;

    public WebAccountRepository(DatabaseManager db) {
        this.db = db;
    }

    public static class AccountData {
        public int id;
        public String discordId;
        public String googleId;
        public String vkId;
        public String telegramId;
        public String username;
        public String passwordHash;
        public boolean isBanned;
        public String banReason;
        public String banExpires; // null = перма
        public String createdAt;
        public String lastLogin;
    }

    private AccountData mapRow(ResultSet rs) throws SQLException {
        AccountData a = new AccountData();
        a.id = rs.getInt("id");
        a.discordId = rs.getString("discord_id");
        a.googleId = rs.getString("google_id");
        a.vkId = rs.getString("vk_id");
        a.telegramId = rs.getString("telegram_id");
        a.username = rs.getString("username");
        a.passwordHash = rs.getString("password_hash");
        a.isBanned = rs.getInt("is_banned") == 1;
        a.banReason = rs.getString("ban_reason");
        a.banExpires = rs.getString("ban_expires");
        a.createdAt = rs.getString("created_at");
        a.lastLogin = rs.getString("last_login");
        return a;
    }

    // возвращает id нового аккаунта или -1
    public int createAccount(String discordId, String googleId, String vkId,
                             String telegramId, String username) {
        String sql = "INSERT INTO web_accounts (discord_id, google_id, vk_id, telegram_id, username) VALUES (?, ?, ?, ?, ?)";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql, PreparedStatement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, nullIfEmpty(discordId));
            ps.setString(2, nullIfEmpty(googleId));
            ps.setString(3, nullIfEmpty(vkId));
            ps.setString(4, nullIfEmpty(telegramId));
            ps.setString(5, username);
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                if (rs.next()) return rs.getInt(1);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return -1;
    }

    public AccountData getAccount(int accountId) {
        String sql = "SELECT * FROM web_accounts WHERE id = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return mapRow(rs);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public AccountData getAccountByDiscordId(String discordId) {
        String sql = "SELECT * FROM web_accounts WHERE discord_id = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, discordId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return mapRow(rs);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public AccountData getAccountByGoogleId(String googleId) {
        String sql = "SELECT * FROM web_accounts WHERE google_id = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, googleId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return mapRow(rs);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public AccountData getAccountByVkId(String vkId) {
        String sql = "SELECT * FROM web_accounts WHERE vk_id = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, vkId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return mapRow(rs);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public AccountData getAccountByTelegramId(String telegramId) {
        String sql = "SELECT * FROM web_accounts WHERE telegram_id = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, telegramId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return mapRow(rs);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    // ищет аккаунт через web_account_nicks
    public AccountData getAccountByNick(String minecraftNick) {
        String sql = """
            SELECT wa.* FROM web_accounts wa
            JOIN web_account_nicks wan ON wa.id = wan.account_id
            WHERE wan.minecraft_nick = ?
        """;
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, minecraftNick);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return mapRow(rs);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    // привязка соцсетей, только если поле пустое
    public boolean linkDiscord(int accountId, String discordId) {
        String sql = "UPDATE web_accounts SET discord_id = ? WHERE id = ? AND (discord_id IS NULL OR discord_id = '')";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, discordId);
            ps.setInt(2, accountId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean linkGoogle(int accountId, String googleId) {
        String sql = "UPDATE web_accounts SET google_id = ? WHERE id = ? AND (google_id IS NULL OR google_id = '')";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, googleId);
            ps.setInt(2, accountId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean linkVk(int accountId, String vkId) {
        String sql = "UPDATE web_accounts SET vk_id = ? WHERE id = ? AND (vk_id IS NULL OR vk_id = '')";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, vkId);
            ps.setInt(2, accountId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean linkTelegram(int accountId, String telegramId) {
        String sql = "UPDATE web_accounts SET telegram_id = ? WHERE id = ? AND (telegram_id IS NULL OR telegram_id = '')";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, telegramId);
            ps.setInt(2, accountId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    // есть ли хоть одна привязанная соцсеть — если да, /login -> /profile
    public boolean hasSocialLink(int accountId) {
        String sql = "SELECT discord_id, google_id, vk_id, telegram_id FROM web_accounts WHERE id = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return isNotEmpty(rs.getString("discord_id"))
                        || isNotEmpty(rs.getString("google_id"))
                        || isNotEmpty(rs.getString("vk_id"))
                        || isNotEmpty(rs.getString("telegram_id"));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    // сессии

    public boolean createSession(int accountId, String token, String ip, String expiresAt) {
        String sql = "INSERT INTO web_sessions (account_id, token, ip_address, expires_at) VALUES (?, ?, ?, ?)";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            ps.setString(2, token);
            ps.setString(3, ip);
            ps.setString(4, expiresAt);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    // возвращает id аккаунта или -1
    public int validateSession(String token) {
        if (token == null || token.isEmpty()) return -1;
        String sql = """
            SELECT account_id FROM web_sessions
            WHERE token = ? AND expires_at > datetime('now')
        """;
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, token);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getInt("account_id");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return -1;
    }

    public boolean deleteSession(String token) {
        String sql = "DELETE FROM web_sessions WHERE token = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, token);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean deleteSessionsByAccount(int accountId) {
        String sql = "DELETE FROM web_sessions WHERE account_id = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean updateLastLogin(int accountId) {
        String sql = "UPDATE web_accounts SET last_login = datetime('now') WHERE id = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    // баны

    public boolean banAccount(int accountId, String reason) {
        return banAccount(accountId, reason, null);
    }

    // expiresAt = null -> перманент
    public boolean banAccount(int accountId, String reason, String expiresAt) {
        String sql = "UPDATE web_accounts SET is_banned = 1, ban_reason = ?, ban_expires = ? WHERE id = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, reason);
            ps.setString(2, expiresAt);
            ps.setInt(3, accountId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean unbanAccount(int accountId) {
        String sql = "UPDATE web_accounts SET is_banned = 0, ban_reason = NULL, ban_expires = NULL WHERE id = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    // снимает истёкшие баны автоматически
    public boolean isAccountBanned(int accountId) {
        String expireSql = "UPDATE web_accounts SET is_banned = 0, ban_reason = NULL, ban_expires = NULL WHERE id = ? AND is_banned = 1 AND ban_expires IS NOT NULL AND ban_expires < datetime('now')";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(expireSql)) {
            ps.setInt(1, accountId);
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }

        String sql = "SELECT is_banned FROM web_accounts WHERE id = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getInt("is_banned") == 1;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    // для админки

    public List<AccountData> getAllAccounts() {
        String sql = "SELECT * FROM web_accounts ORDER BY id DESC";
        List<AccountData> list = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) list.add(mapRow(rs));
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    public int getAccountCount() {
        String sql = "SELECT COUNT(*) FROM web_accounts";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0;
    }

    public int getBannedAccountCount() {
        String sql = "SELECT COUNT(*) FROM web_accounts WHERE is_banned = 1";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0;
    }

    // забаненные аккаунты + их ники через group_concat
    public List<BannedAccountInfo> getBannedAccounts() {
        String sql = """
            SELECT wa.id, wa.username, wa.ban_reason, wa.ban_expires, wa.is_banned,
                   GROUP_CONCAT(wan.minecraft_nick) as nicks
            FROM web_accounts wa
            LEFT JOIN web_account_nicks wan ON wa.id = wan.account_id
            WHERE wa.is_banned = 1
            GROUP BY wa.id
            ORDER BY wa.ban_expires ASC
        """;
        List<BannedAccountInfo> list = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                BannedAccountInfo info = new BannedAccountInfo();
                info.accountId = rs.getInt("id");
                info.username = rs.getString("username");
                info.banReason = rs.getString("ban_reason");
                info.banExpires = rs.getString("ban_expires");
                info.nicks = rs.getString("nicks");
                list.add(info);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    public static class BannedAccountInfo {
        public int accountId;
        public String username;
        public String banReason;
        public String banExpires;
        public String nicks;
    }

    private String nullIfEmpty(String s) {
        return (s == null || s.isEmpty()) ? null : s;
    }

    private boolean isNotEmpty(String s) {
        return s != null && !s.isEmpty();
    }
}
