package com.antivirus.db;

import com.antivirus.model.ThreatRecord;
import com.antivirus.model.ScanResult;
import com.antivirus.util.PasswordHasher;

import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Gère la persistance des données (historique scans, menaces) via SQLite.
 */
public class DatabaseManager {

    private static final String DB_URL = "jdbc:sqlite:antivirus.db";
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private static DatabaseManager instance;

    private DatabaseManager() {
        initDatabase();
    }

    public static synchronized DatabaseManager getInstance() {
        if (instance == null) {
            instance = new DatabaseManager();
        }
        return instance;
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    private void initDatabase() {
        String createScansTable = """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target_path TEXT NOT NULL,
                files_scanned INTEGER DEFAULT 0,
                threats_found INTEGER DEFAULT 0,
                start_time TEXT NOT NULL,
                end_time TEXT
            );
        """;

        String createThreatsTable = """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                file_path TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_hash TEXT,
                type TEXT NOT NULL,
                threat_name TEXT NOT NULL,
                status TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                file_size INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
        """;

        String createUsersTable = """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """;

        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {
            stmt.execute(createScansTable);
            stmt.execute(createThreatsTable);
            stmt.execute(createUsersTable);
            
            // Créer l'utilisateur admin par défaut s'il n'existe pas
            createDefaultAdminUser(conn);
        } catch (SQLException e) {
            System.err.println("Erreur initialisation BD: " + e.getMessage());
        }
    }

    private void createDefaultAdminUser(Connection conn) throws SQLException {
        String checkAdmin = "SELECT COUNT(*) FROM users WHERE username = 'admin'";
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(checkAdmin)) {
            if (rs.next() && rs.getInt(1) == 0) {
                // L'admin n'existe pas, le créer
                String insertAdmin = "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)";
                try (PreparedStatement ps = conn.prepareStatement(insertAdmin)) {
                    ps.setString(1, "admin");
                    ps.setString(2, PasswordHasher.hashPassword("admin123@"));
                    ps.setString(3, LocalDateTime.now().format(FORMATTER));
                    ps.executeUpdate();
                    System.out.println("Utilisateur admin créé par défaut");
                }
            }
        }
    }

    /**
     * Enregistre un scan complet et ses menaces associées.
     * Retourne l'ID du scan inséré.
     */
    public int saveScanResult(ScanResult result) {
        String insertScan = """
            INSERT INTO scans (scan_type, target_path, files_scanned, threats_found, start_time, end_time)
            VALUES (?, ?, ?, ?, ?, ?)
        """;

        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(insertScan, Statement.RETURN_GENERATED_KEYS)) {

            ps.setString(1, result.getScanType().name());
            ps.setString(2, result.getTargetPath());
            ps.setInt(3, result.getFilesScanned());
            ps.setInt(4, result.getThreatsFound());
            ps.setString(5, result.getStartTime().format(FORMATTER));
            ps.setString(6, result.getEndTime() != null ? result.getEndTime().format(FORMATTER) : null);

            ps.executeUpdate();

            ResultSet rs = ps.getGeneratedKeys();
            int scanId = -1;
            if (rs.next()) {
                scanId = rs.getInt(1);
            }

            // Sauvegarder les menaces associées
            for (ThreatRecord threat : result.getThreats()) {
                saveThreat(conn, scanId, threat);
            }

            return scanId;

        } catch (SQLException e) {
            System.err.println("Erreur sauvegarde scan: " + e.getMessage());
            return -1;
        }
    }

    private void saveThreat(Connection conn, int scanId, ThreatRecord threat) throws SQLException {
        String insertThreat = """
            INSERT INTO threats (scan_id, file_path, file_name, file_hash, type, threat_name, status, detected_at, file_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """;

        try (PreparedStatement ps = conn.prepareStatement(insertThreat, Statement.RETURN_GENERATED_KEYS)) {
            ps.setInt(1, scanId);
            ps.setString(2, threat.getFilePath());
            ps.setString(3, threat.getFileName());
            ps.setString(4, threat.getFileHash());
            ps.setString(5, threat.getType().name());
            ps.setString(6, threat.getThreatName());
            ps.setString(7, threat.getStatus().name());
            ps.setString(8, threat.getDetectedAt().format(FORMATTER));
            ps.setLong(9, threat.getFileSize());

            ps.executeUpdate();

            ResultSet rs = ps.getGeneratedKeys();
            if (rs.next()) {
                threat.setId(rs.getInt(1));
            }
        }
    }

    /**
     * Met à jour le statut d'une menace (ex: après mise en quarantaine).
     */
    public void updateThreatStatus(int threatId, ThreatRecord.ThreatStatus status) {
        String sql = "UPDATE threats SET status = ? WHERE id = ?";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, status.name());
            ps.setInt(2, threatId);
            ps.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Erreur mise à jour menace: " + e.getMessage());
        }
    }

    /**
     * Récupère toutes les menaces enregistrées (pour le dashboard).
     */
    public List<ThreatRecord> getAllThreats() {
        List<ThreatRecord> threats = new ArrayList<>();
        String sql = "SELECT * FROM threats ORDER BY detected_at DESC";

        try (Connection conn = connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                threats.add(mapResultSetToThreat(rs));
            }

        } catch (SQLException e) {
            System.err.println("Erreur récupération menaces: " + e.getMessage());
        }

        return threats;
    }

    /**
     * Récupère les menaces actuellement en quarantaine.
     */
    public List<ThreatRecord> getQuarantinedThreats() {
        List<ThreatRecord> threats = new ArrayList<>();
        String sql = "SELECT * FROM threats WHERE status = ? ORDER BY detected_at DESC";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ThreatRecord.ThreatStatus.QUARANTINED.name());
            ResultSet rs = ps.executeQuery();

            while (rs.next()) {
                threats.add(mapResultSetToThreat(rs));
            }

        } catch (SQLException e) {
            System.err.println("Erreur récupération quarantaine: " + e.getMessage());
        }

        return threats;
    }

    /**
     * Récupère l'historique des scans (pour graphiques dashboard).
     */
    public List<ScanResult> getScanHistory(int limit) {
        List<ScanResult> scans = new ArrayList<>();
        String sql = "SELECT * FROM scans ORDER BY start_time DESC LIMIT ?";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit);
            ResultSet rs = ps.executeQuery();

            while (rs.next()) {
                ScanResult sr = new ScanResult(
                        ScanResult.ScanType.valueOf(rs.getString("scan_type")),
                        rs.getString("target_path")
                );
                sr.setId(rs.getInt("id"));
                sr.setFilesScanned(rs.getInt("files_scanned"));
                sr.setThreatsFound(rs.getInt("threats_found"));
                sr.setStartTime(LocalDateTime.parse(rs.getString("start_time"), FORMATTER));
                String endTime = rs.getString("end_time");
                if (endTime != null) {
                    sr.setEndTime(LocalDateTime.parse(endTime, FORMATTER));
                }
                scans.add(sr);
            }

        } catch (SQLException e) {
            System.err.println("Erreur récupération historique: " + e.getMessage());
        }

        return scans;
    }

    /**
     * Statistiques globales pour le dashboard.
     */
    public int getTotalScansCount() {
        return getCount("SELECT COUNT(*) FROM scans");
    }

    public int getTotalThreatsCount() {
        return getCount("SELECT COUNT(*) FROM threats");
    }

    public int getQuarantinedCount() {
        return getCount("SELECT COUNT(*) FROM threats WHERE status = 'QUARANTINED'");
    }

    public int getTotalFilesScanned() {
        return getCount("SELECT SUM(files_scanned) FROM scans");
    }

    private int getCount(String sql) {
        try (Connection conn = connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            System.err.println("Erreur comptage: " + e.getMessage());
        }
        return 0;
    }

    private ThreatRecord mapResultSetToThreat(ResultSet rs) throws SQLException {
        ThreatRecord threat = new ThreatRecord();
        threat.setId(rs.getInt("id"));
        threat.setFilePath(rs.getString("file_path"));
        threat.setFileName(rs.getString("file_name"));
        threat.setFileHash(rs.getString("file_hash"));
        threat.setType(ThreatRecord.ThreatType.valueOf(rs.getString("type")));
        threat.setThreatName(rs.getString("threat_name"));
        threat.setStatus(ThreatRecord.ThreatStatus.valueOf(rs.getString("status")));
        threat.setDetectedAt(LocalDateTime.parse(rs.getString("detected_at"), FORMATTER));
        threat.setFileSize(rs.getLong("file_size"));
        return threat;
    }

    /**
     * Authentifie un utilisateur avec username et password.
     * @param username Le nom d'utilisateur
     * @param password Le mot de passe en clair
     * @return true si l'authentification réussit
     */
    public boolean authenticateUser(String username, String password) {
        String sql = "SELECT password_hash FROM users WHERE username = ?";
        
        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            ResultSet rs = ps.executeQuery();
            
            if (rs.next()) {
                String storedHash = rs.getString("password_hash");
                return PasswordHasher.verifyPassword(password, storedHash);
            }
        } catch (SQLException e) {
            System.err.println("Erreur authentification: " + e.getMessage());
        }
        return false;
    }

    /**
     * Ajoute un nouvel utilisateur.
     * @param username Le nom d'utilisateur
     * @param password Le mot de passe en clair
     * @return true si l'utilisateur est créé avec succès
     */
    public boolean addUser(String username, String password) {
        String sql = "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)";
        
        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setString(2, PasswordHasher.hashPassword(password));
            ps.setString(3, LocalDateTime.now().format(FORMATTER));
            ps.executeUpdate();
            return true;
        } catch (SQLException e) {
            System.err.println("Erreur création utilisateur: " + e.getMessage());
            return false;
        }
    }

    /**
     * Change le mot de passe d'un utilisateur.
     * @param username Le nom d'utilisateur
     * @param oldPassword L'ancien mot de passe (pour vérification)
     * @param newPassword Le nouveau mot de passe
     * @return true si le changement a réussi
     */
    public boolean changePassword(String username, String oldPassword, String newPassword) {
        // Vérifier d'abord l'ancien mot de passe
        if (!authenticateUser(username, oldPassword)) {
            return false;
        }

        String sql = "UPDATE users SET password_hash = ? WHERE username = ?";
        
        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, PasswordHasher.hashPassword(newPassword));
            ps.setString(2, username);
            int rowsUpdated = ps.executeUpdate();
            return rowsUpdated > 0;
        } catch (SQLException e) {
            System.err.println("Erreur changement mot de passe: " + e.getMessage());
            return false;
        }
    }
}
