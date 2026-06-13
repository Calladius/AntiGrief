package com.antigrief.database;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.io.File;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

// sqlite с пулом соединений hikaricp
public class DatabaseManager {

    private HikariDataSource dataSource;
    private final File dataFolder;

    public DatabaseManager(File dataFolder) {
        this.dataFolder = dataFolder;
    }

    public void connect() throws SQLException {
        File dbFile = new File(dataFolder, "data.db");
        String jdbcUrl = "jdbc:sqlite:" + dbFile.getAbsolutePath();

        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(jdbcUrl);
        config.setMaximumPoolSize(5);
        config.setAutoCommit(true);
        config.addDataSourceProperty("journal_mode", "WAL");
        config.addDataSourceProperty("synchronous", "NORMAL");
        config.addDataSourceProperty("foreign_keys", "true");

        dataSource = new HikariDataSource(config);
        createTables();
    }

    public Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }

    public void disconnect() {
        if (dataSource != null && !dataSource.isClosed()) dataSource.close();
    }

    private void createTables() throws SQLException {
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS web_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    discord_id TEXT,
                    google_id TEXT,
                    vk_id TEXT,
                    telegram_id TEXT,
                    username TEXT NOT NULL,
                    password_hash TEXT,
                    is_banned INTEGER DEFAULT 0,
                    ban_reason TEXT,
                    ban_expires TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    last_login TEXT
                )
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS web_account_nicks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL REFERENCES web_accounts(id) ON DELETE CASCADE,
                    minecraft_nick TEXT NOT NULL UNIQUE,
                    linked_at TEXT DEFAULT (datetime('now'))
                )
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS web_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL REFERENCES web_accounts(id) ON DELETE CASCADE,
                    token TEXT NOT NULL UNIQUE,
                    ip_address TEXT NOT NULL,
                    created_at TEXT DEFAULT (datetime('now')),
                    expires_at TEXT NOT NULL
                )
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS player_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    minecraft_nick TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    first_seen TEXT DEFAULT (datetime('now')),
                    last_seen TEXT DEFAULT (datetime('now'))
                )
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS fingerprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint_hash TEXT NOT NULL,
                    web_account_id INTEGER NOT NULL REFERENCES web_accounts(id) ON DELETE CASCADE,
                    ip_address TEXT NOT NULL,
                    browser_data TEXT,
                    first_seen TEXT DEFAULT (datetime('now')),
                    last_seen TEXT DEFAULT (datetime('now'))
                )
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS fingerprint_bans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint_hash TEXT NOT NULL UNIQUE,
                    reason TEXT,
                    banned_at TEXT DEFAULT (datetime('now'))
                )
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS ip_bans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    reason TEXT,
                    banned_by TEXT,
                    banned_at TEXT DEFAULT (datetime('now')),
                    expires_at TEXT
                )
            """);

            // устройственные отпечатки — стабильны при смене браузера
            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS device_fingerprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_hash TEXT NOT NULL,
                    web_account_id INTEGER NOT NULL REFERENCES web_accounts(id) ON DELETE CASCADE,
                    ip_address TEXT NOT NULL,
                    webrtc_ip TEXT,
                    first_seen TEXT DEFAULT (datetime('now')),
                    last_seen TEXT DEFAULT (datetime('now'))
                )
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS device_bans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_hash TEXT NOT NULL UNIQUE,
                    reason TEXT,
                    banned_at TEXT DEFAULT (datetime('now'))
                )
            """);

            // индексы
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_nicks_account ON web_account_nicks(account_id)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_nicks_nick ON web_account_nicks(minecraft_nick)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_sessions_token ON web_sessions(token)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_sessions_account ON web_sessions(account_id)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON web_sessions(expires_at)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_ips_nick ON player_ips(minecraft_nick)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_ips_ip ON player_ips(ip_address)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_fp_hash ON fingerprints(fingerprint_hash)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_fp_account ON fingerprints(web_account_id)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_device_hash ON device_fingerprints(device_hash)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_device_account ON device_fingerprints(web_account_id)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_discord_id ON web_accounts(discord_id)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_google_id ON web_accounts(google_id)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_vk_id ON web_accounts(vk_id)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_telegram_id ON web_accounts(telegram_id)");

            // миграции
            migrateTable(conn, "web_accounts", "ban_expires", "TEXT");
            migrateTable(conn, "web_accounts", "last_login", "TEXT");
            migrateTable(conn, "ip_bans", "ban_expires", "TEXT");
        }
    }

    // добавляет колонку если её нет
    private void migrateTable(Connection conn, String table, String column, String type) {
        try {
            var rs = conn.createStatement().executeQuery("PRAGMA table_info(" + table + ")");
            boolean found = false;
            while (rs.next()) {
                if (column.equalsIgnoreCase(rs.getString("name"))) { found = true; break; }
            }
            rs.close();
            if (!found) {
                conn.createStatement().executeUpdate("ALTER TABLE " + table + " ADD COLUMN " + column + " " + type);
                System.out.println("[AntiGrief] миграция: +" + column + " в " + table);
            }
        } catch (SQLException e) {
            System.out.println("[AntiGrief] миграция " + column + ": " + e.getMessage());
        }
    }

    public void deleteDatabase() {
        disconnect();
        new File(dataFolder, "data.db").delete();
        new File(dataFolder, "data.db-wal").delete();
        new File(dataFolder, "data.db-shm").delete();
    }
}
