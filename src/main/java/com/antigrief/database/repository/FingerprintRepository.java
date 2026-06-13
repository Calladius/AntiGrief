package com.antigrief.database.repository;

import com.antigrief.database.DatabaseManager;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

// отпечатки браузера (sha256 от ~70 параметров), для поиска мультиков

public class FingerprintRepository {

    private final DatabaseManager db;

    public FingerprintRepository(DatabaseManager db) {
        this.db = db;
    }

    public static class FingerprintRecord {
        public int id;
        public String fingerprintHash;
        public int webAccountId;
        public String ipAddress;
        public String browserData;
        public String firstSeen;
        public String lastSeen;
    }

    public static class MultiAccountRecord {
        public String fingerprintHash;
        public int accountCount;
        public List<Integer> accountIds;
    }

    public static class FingerprintBan {
        public int id;
        public String fingerprintHash;
        public String reason;
        public String bannedAt;
    }

    // upsert: если есть — обновит last_seen
    public boolean recordFingerprint(String fingerprintHash, int accountId, String ip, String browserData) {
        String checkSql = "SELECT id FROM fingerprints WHERE fingerprint_hash = ? AND web_account_id = ?";
        try (Connection conn = db.getConnection()) {
            try (PreparedStatement ps = conn.prepareStatement(checkSql)) {
                ps.setString(1, fingerprintHash);
                ps.setInt(2, accountId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        String updateSql = "UPDATE fingerprints SET last_seen = datetime('now'), ip_address = ? WHERE fingerprint_hash = ? AND web_account_id = ?";
                        try (PreparedStatement ups = conn.prepareStatement(updateSql)) {
                            ups.setString(1, ip);
                            ups.setString(2, fingerprintHash);
                            ups.setInt(3, accountId);
                            return ups.executeUpdate() > 0;
                        }
                    }
                }
            }
            String insertSql = "INSERT INTO fingerprints (fingerprint_hash, web_account_id, ip_address, browser_data) VALUES (?, ?, ?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                ps.setString(1, fingerprintHash);
                ps.setInt(2, accountId);
                ps.setString(3, ip);
                ps.setString(4, browserData);
                return ps.executeUpdate() > 0;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public List<FingerprintRecord> getFingerprintsByAccount(int accountId) {
        String sql = "SELECT * FROM fingerprints WHERE web_account_id = ? ORDER BY last_seen DESC";
        List<FingerprintRecord> list = new ArrayList<>();
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

    // основной метод для детекции мультиков
    public List<Integer> getAccountsByFingerprint(String fingerprintHash) {
        String sql = "SELECT DISTINCT web_account_id FROM fingerprints WHERE fingerprint_hash = ?";
        List<Integer> ids = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, fingerprintHash);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) ids.add(rs.getInt("web_account_id"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return ids;
    }

    // отпечатки с >1 аккаунтом
    public List<MultiAccountRecord> getMultiAccountFingerprints() {
        String sql = """
            SELECT fingerprint_hash, COUNT(DISTINCT web_account_id) as cnt
            FROM fingerprints
            GROUP BY fingerprint_hash
            HAVING cnt > 1
            ORDER BY cnt DESC
        """;
        List<MultiAccountRecord> list = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                MultiAccountRecord r = new MultiAccountRecord();
                r.fingerprintHash = rs.getString("fingerprint_hash");
                r.accountCount = rs.getInt("cnt");
                r.accountIds = getAccountsByFingerprint(r.fingerprintHash);
                list.add(r);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    // баны отпечатков — аккаунты забанятся при следующей проверке

    public boolean banFingerprint(String fingerprintHash, String reason) {
        String sql = "INSERT OR REPLACE INTO fingerprint_bans (fingerprint_hash, reason) VALUES (?, ?)";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, fingerprintHash);
            ps.setString(2, reason);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean unbanFingerprint(String fingerprintHash) {
        String sql = "DELETE FROM fingerprint_bans WHERE fingerprint_hash = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, fingerprintHash);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean isFingerprintBanned(String fingerprintHash) {
        String sql = "SELECT 1 FROM fingerprint_bans WHERE fingerprint_hash = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, fingerprintHash);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public String getFingerprintBanReason(String fingerprintHash) {
        String sql = "SELECT reason FROM fingerprint_bans WHERE fingerprint_hash = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, fingerprintHash);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getString("reason");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public List<FingerprintBan> getAllBannedFingerprints() {
        String sql = "SELECT * FROM fingerprint_bans ORDER BY banned_at DESC";
        List<FingerprintBan> list = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                FingerprintBan b = new FingerprintBan();
                b.id = rs.getInt("id");
                b.fingerprintHash = rs.getString("fingerprint_hash");
                b.reason = rs.getString("reason");
                b.bannedAt = rs.getString("banned_at");
                list.add(b);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    public List<FingerprintRecord> getAllFingerprints() {
        String sql = "SELECT * FROM fingerprints ORDER BY last_seen DESC LIMIT 500";
        List<FingerprintRecord> list = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) list.add(mapRow(rs));
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    // для блокировки входа с ip забаненного
    public int getBannedAccountIdByIp(String ipAddress) {
        String sql = """
            SELECT f.web_account_id FROM fingerprints f
            JOIN web_accounts wa ON f.web_account_id = wa.id
            WHERE f.ip_address = ? AND wa.is_banned = 1
            LIMIT 1
        """;
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ipAddress);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getInt(1);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return -1;
    }

    private FingerprintRecord mapRow(ResultSet rs) throws SQLException {
        FingerprintRecord r = new FingerprintRecord();
        r.id = rs.getInt("id");
        r.fingerprintHash = rs.getString("fingerprint_hash");
        r.webAccountId = rs.getInt("web_account_id");
        r.ipAddress = rs.getString("ip_address");
        r.browserData = rs.getString("browser_data");
        r.firstSeen = rs.getString("first_seen");
        r.lastSeen = rs.getString("last_seen");
        return r;
    }
}
