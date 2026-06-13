package com.antigrief.database.repository;

import com.antigrief.database.DatabaseManager;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

// ники minecraft привязанные к веб-аккаунтам, один ник = один аккаунт

public class PlayerNickRepository {

    private final DatabaseManager db;

    public PlayerNickRepository(DatabaseManager db) {
        this.db = db;
    }

    // false если ник уже занят
    public boolean linkNick(int accountId, String minecraftNick) {
        String sql = "INSERT INTO web_account_nicks (account_id, minecraft_nick) VALUES (?, ?)";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            ps.setString(2, minecraftNick);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            return false;
        }
    }

    public boolean unlinkNick(int accountId, String minecraftNick) {
        String sql = "DELETE FROM web_account_nicks WHERE account_id = ? AND minecraft_nick = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            ps.setString(2, minecraftNick);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public List<String> getNicksByAccount(int accountId) {
        String sql = "SELECT minecraft_nick FROM web_account_nicks WHERE account_id = ? ORDER BY linked_at";
        List<String> nicks = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) nicks.add(rs.getString("minecraft_nick"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return nicks;
    }

    // -1 если не привязан
    public int getAccountIdByNick(String minecraftNick) {
        String sql = "SELECT account_id FROM web_account_nicks WHERE minecraft_nick = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, minecraftNick);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getInt("account_id");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return -1;
    }

    public boolean isNickLinked(String minecraftNick) {
        return getAccountIdByNick(minecraftNick) > 0;
    }

    public boolean isNickLinkedToAccount(int accountId, String minecraftNick) {
        String sql = "SELECT 1 FROM web_account_nicks WHERE account_id = ? AND minecraft_nick = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            ps.setString(2, minecraftNick);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public int getNickCount(int accountId) {
        String sql = "SELECT COUNT(*) FROM web_account_nicks WHERE account_id = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getInt(1);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0;
    }

    public List<String> getAllLinkedNicks() {
        String sql = "SELECT minecraft_nick FROM web_account_nicks ORDER BY minecraft_nick";
        List<String> nicks = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) nicks.add(rs.getString("minecraft_nick"));
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return nicks;
    }

    public List<String> getBannedNicks() {
        String sql = """
            SELECT wan.minecraft_nick FROM web_account_nicks wan
            JOIN web_accounts wa ON wan.account_id = wa.id
            WHERE wa.is_banned = 1
            ORDER BY wan.minecraft_nick
        """;
        List<String> nicks = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) nicks.add(rs.getString("minecraft_nick"));
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return nicks;
    }

    public List<String> getUnbannedNicks() {
        String sql = """
            SELECT wan.minecraft_nick FROM web_account_nicks wan
            JOIN web_accounts wa ON wan.account_id = wa.id
            WHERE wa.is_banned = 0
            ORDER BY wan.minecraft_nick
        """;
        List<String> nicks = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) nicks.add(rs.getString("minecraft_nick"));
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return nicks;
    }
}
