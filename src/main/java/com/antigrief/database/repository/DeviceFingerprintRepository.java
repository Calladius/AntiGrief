package com.antigrief.database.repository;

import com.antigrief.database.DatabaseManager;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

// device fingerprint = sha256(gpu+шрифты+cpu+ram+экран+tz+platform)
// стабилен при смене браузера, webrtc ip — утечка реального ip мимо vpn

public class DeviceFingerprintRepository {

    private final DatabaseManager db;

    public DeviceFingerprintRepository(DatabaseManager db) {
        this.db = db;
    }

    public static class DeviceFingerprintRecord {
        public int id;
        public String deviceHash;
        public int webAccountId;
        public String ipAddress;
        public String webrtcIp;
        public String firstSeen;
        public String lastSeen;
    }

    public static class DeviceBan {
        public int id;
        public String deviceHash;
        public String reason;
        public String bannedAt;
    }

    // upsert: обновит last_seen если запись есть
    public boolean recordDeviceFingerprint(String deviceHash, int accountId, String ip, String webrtcIp) {
        if (deviceHash == null || deviceHash.isEmpty()) return false;

        String checkSql = "SELECT id FROM device_fingerprints WHERE device_hash = ? AND web_account_id = ?";
        try (Connection conn = db.getConnection()) {
            try (PreparedStatement ps = conn.prepareStatement(checkSql)) {
                ps.setString(1, deviceHash);
                ps.setInt(2, accountId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        String updateSql = "UPDATE device_fingerprints SET last_seen = datetime('now'), ip_address = ?, webrtc_ip = ? WHERE device_hash = ? AND web_account_id = ?";
                        try (PreparedStatement ups = conn.prepareStatement(updateSql)) {
                            ups.setString(1, ip);
                            ups.setString(2, webrtcIp);
                            ups.setString(3, deviceHash);
                            ups.setInt(4, accountId);
                            return ups.executeUpdate() > 0;
                        }
                    }
                }
            }
            String insertSql = "INSERT INTO device_fingerprints (device_hash, web_account_id, ip_address, webrtc_ip) VALUES (?, ?, ?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                ps.setString(1, deviceHash);
                ps.setInt(2, accountId);
                ps.setString(3, ip);
                ps.setString(4, webrtcIp);
                return ps.executeUpdate() > 0;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    // для детекции мультиков с одного устройства
    public List<Integer> getAccountsByDevice(String deviceHash) {
        String sql = "SELECT DISTINCT web_account_id FROM device_fingerprints WHERE device_hash = ?";
        List<Integer> ids = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, deviceHash);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) ids.add(rs.getInt("web_account_id"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return ids;
    }

    public List<DeviceFingerprintRecord> getDeviceFingerprintsByAccount(int accountId) {
        String sql = "SELECT * FROM device_fingerprints WHERE web_account_id = ? ORDER BY last_seen DESC";
        List<DeviceFingerprintRecord> list = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) list.add(mapRow(rs));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    // последний deviceHash аккаунта
    public String getDeviceHashByAccount(int accountId) {
        String sql = "SELECT device_hash FROM device_fingerprints WHERE web_account_id = ? ORDER BY last_seen DESC LIMIT 1";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getString("device_hash");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    // баны устройств — аккаунты забанятся при следующей проверке

    public boolean banDevice(String deviceHash, String reason) {
        String sql = "INSERT OR REPLACE INTO device_bans (device_hash, reason) VALUES (?, ?)";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, deviceHash);
            ps.setString(2, reason);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean unbanDevice(String deviceHash) {
        String sql = "DELETE FROM device_bans WHERE device_hash = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, deviceHash);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean isDeviceBanned(String deviceHash) {
        if (deviceHash == null || deviceHash.isEmpty()) return false;
        String sql = "SELECT 1 FROM device_bans WHERE device_hash = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, deviceHash);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public String getDeviceBanReason(String deviceHash) {
        String sql = "SELECT reason FROM device_bans WHERE device_hash = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, deviceHash);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getString("reason");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public List<DeviceBan> getAllBannedDevices() {
        String sql = "SELECT * FROM device_bans ORDER BY banned_at DESC";
        List<DeviceBan> list = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                DeviceBan b = new DeviceBan();
                b.id = rs.getInt("id");
                b.deviceHash = rs.getString("device_hash");
                b.reason = rs.getString("reason");
                b.bannedAt = rs.getString("banned_at");
                list.add(b);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    public List<DeviceFingerprintRecord> getAllDeviceFingerprints() {
        String sql = "SELECT * FROM device_fingerprints ORDER BY last_seen DESC LIMIT 500";
        List<DeviceFingerprintRecord> list = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) list.add(mapRow(rs));
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    private DeviceFingerprintRecord mapRow(ResultSet rs) throws SQLException {
        DeviceFingerprintRecord r = new DeviceFingerprintRecord();
        r.id = rs.getInt("id");
        r.deviceHash = rs.getString("device_hash");
        r.webAccountId = rs.getInt("web_account_id");
        r.ipAddress = rs.getString("ip_address");
        r.webrtcIp = rs.getString("webrtc_ip");
        r.firstSeen = rs.getString("first_seen");
        r.lastSeen = rs.getString("last_seen");
        return r;
    }
}
