package com.antigrief.database.repository;

import com.antigrief.database.DatabaseManager;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

// история ip игроков, для поиска мультиков

public class PlayerIpRepository {

    private final DatabaseManager db;

    public PlayerIpRepository(DatabaseManager db) {
        this.db = db;
    }

    public static class IpRecord {
        public String minecraftNick;
        public String ipAddress;
        public String asn;
        public String firstSeen;
        public String lastSeen;
    }

    // upsert: если запись есть — обновит last_seen и asn
    public boolean recordIp(String minecraftNick, String ipAddress, String asn) {
        String checkSql = "SELECT id FROM player_ips WHERE minecraft_nick = ? AND ip_address = ?";
        try (Connection conn = db.getConnection()) {
            try (PreparedStatement ps = conn.prepareStatement(checkSql)) {
                ps.setString(1, minecraftNick);
                ps.setString(2, ipAddress);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        String updateSql = "UPDATE player_ips SET last_seen = datetime('now'), asn = ? WHERE minecraft_nick = ? AND ip_address = ?";
                        try (PreparedStatement ups = conn.prepareStatement(updateSql)) {
                            ups.setString(1, asn);
                            ups.setString(2, minecraftNick);
                            ups.setString(3, ipAddress);
                            return ups.executeUpdate() > 0;
                        }
                    }
                }
            }
            String insertSql = "INSERT INTO player_ips (minecraft_nick, ip_address, asn) VALUES (?, ?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                ps.setString(1, minecraftNick);
                ps.setString(2, ipAddress);
                ps.setString(3, asn);
                return ps.executeUpdate() > 0;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    // обратная совместимость — без asn
    public boolean recordIp(String minecraftNick, String ipAddress) {
        return recordIp(minecraftNick, ipAddress, null);
    }

    public List<IpRecord> getIpsByNick(String minecraftNick) {
        String sql = "SELECT * FROM player_ips WHERE minecraft_nick = ? ORDER BY last_seen DESC";
        List<IpRecord> list = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, minecraftNick);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    IpRecord r = new IpRecord();
                    r.minecraftNick = rs.getString("minecraft_nick");
                    r.ipAddress = rs.getString("ip_address");
                    r.asn = rs.getString("asn");
                    r.firstSeen = rs.getString("first_seen");
                    r.lastSeen = rs.getString("last_seen");
                    list.add(r);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    // для детекции мультиков
    public List<String> getNicksByIp(String ipAddress) {
        String sql = "SELECT DISTINCT minecraft_nick FROM player_ips WHERE ip_address = ? ORDER BY last_seen DESC";
        List<String> nicks = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ipAddress);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) nicks.add(rs.getString("minecraft_nick"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return nicks;
    }

    public List<IpRecord> getAllRecords() {
        String sql = "SELECT * FROM player_ips ORDER BY last_seen DESC LIMIT 500";
        List<IpRecord> list = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                IpRecord r = new IpRecord();
                r.minecraftNick = rs.getString("minecraft_nick");
                r.ipAddress = rs.getString("ip_address");
                r.asn = rs.getString("asn");
                r.firstSeen = rs.getString("first_seen");
                r.lastSeen = rs.getString("last_seen");
                list.add(r);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    // защита от кражи ника на пиратке: новый ip под привязанным ником -> заморозка
    public boolean isIpKnownForNick(String minecraftNick, String ipAddress) {
        String sql = "SELECT 1 FROM player_ips WHERE minecraft_nick = ? AND ip_address = ? LIMIT 1";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, minecraftNick);
            ps.setString(2, ipAddress);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    // проверка asn: был ли у ника ip от того же провайдера (тот же asn)?
    // если да — скорее всего динамическая смена ip, не кража ника
    public boolean isAsnKnownForNick(String minecraftNick, String asn) {
        if (asn == null || asn.isEmpty()) return false;
        String sql = "SELECT 1 FROM player_ips WHERE minecraft_nick = ? AND asn = ? LIMIT 1";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, minecraftNick);
            ps.setString(2, asn);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    // если записей нет — первый заход после привязки
    public boolean hasAnyIpRecord(String minecraftNick) {
        String sql = "SELECT 1 FROM player_ips WHERE minecraft_nick = ? LIMIT 1";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, minecraftNick);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public List<String> getUnbannedIps() {
        String sql = """
            SELECT DISTINCT pi.ip_address FROM player_ips pi
            LEFT JOIN ip_bans ib ON pi.ip_address = ib.ip_address
            WHERE ib.id IS NULL OR (ib.expires_at IS NOT NULL AND ib.expires_at < datetime('now'))
            ORDER BY pi.ip_address
        """;
        List<String> ips = new ArrayList<>();
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) ips.add(rs.getString("ip_address"));
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return ips;
    }
}
