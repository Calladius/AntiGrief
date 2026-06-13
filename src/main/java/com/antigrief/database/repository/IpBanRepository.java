package com.antigrief.database.repository;

import com.antigrief.database.DatabaseManager;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

// баны по ip, перма и временные

public class IpBanRepository {

    private final DatabaseManager db;

    public IpBanRepository(DatabaseManager db) {
        this.db = db;
    }

    public static class IpBan {
        public int id;
        public String ipAddress;
        public String reason;
        public String bannedBy;
        public String bannedAt;
        public String expiresAt; // null = перма
    }

    public boolean banIp(String ip, String reason, String bannedBy) {
        return banIp(ip, reason, bannedBy, null);
    }

    public boolean banIp(String ip, String reason, String bannedBy, String expiresAt) {
        String sql = "INSERT INTO ip_bans (ip_address, reason, banned_by, expires_at) VALUES (?, ?, ?, ?)";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ip);
            ps.setString(2, reason);
            ps.setString(3, bannedBy);
            ps.setString(4, expiresAt);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean unbanIp(String ip) {
        String sql = "DELETE FROM ip_bans WHERE ip_address = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ip);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    // чистит истёкшие баны и возвращает активный или null
    public IpBan getActiveBan(String ip) {
        String expireSql = "DELETE FROM ip_bans WHERE ip_address = ? AND expires_at IS NOT NULL AND expires_at < datetime('now')";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(expireSql)) {
            ps.setString(1, ip);
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }

        String sql = "SELECT * FROM ip_bans WHERE ip_address = ? LIMIT 1";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ip);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    IpBan ban = new IpBan();
                    ban.id = rs.getInt("id");
                    ban.ipAddress = rs.getString("ip_address");
                    ban.reason = rs.getString("reason");
                    ban.bannedBy = rs.getString("banned_by");
                    ban.bannedAt = rs.getString("banned_at");
                    ban.expiresAt = rs.getString("expires_at");
                    return ban;
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public List<IpBan> getAllBans() {
        String sql = "SELECT * FROM ip_bans ORDER BY banned_at DESC";
        List<IpBan> list = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                IpBan ban = new IpBan();
                ban.id = rs.getInt("id");
                ban.ipAddress = rs.getString("ip_address");
                ban.reason = rs.getString("reason");
                ban.bannedBy = rs.getString("banned_by");
                ban.bannedAt = rs.getString("banned_at");
                ban.expiresAt = rs.getString("expires_at");
                list.add(ban);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }
}
