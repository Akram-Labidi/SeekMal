package com.antivirus.model;

import java.time.LocalDateTime;

/**
 * Représente une menace détectée lors d'un scan.
 */
public class ThreatRecord {

    public enum ThreatType {
        SIGNATURE_MATCH,    // Hash correspondant à une signature connue
        HEURISTIC_EXTENSION, // Extension suspecte (.exe, .bat, .vbs déguisé, etc.)
        HEURISTIC_PATTERN,   // Pattern de code suspect (eval, base64_decode, etc.)
        UNKNOWN
    }

    public enum ThreatStatus {
        DETECTED,
        QUARANTINED,
        RESTORED,
        DELETED,
        IGNORED
    }

    private int id;
    private String filePath;
    private String fileName;
    private String fileHash;
    private ThreatType type;
    private String threatName;     // Nom de la menace (ex: "Trojan.Generic")
    private ThreatStatus status;
    private LocalDateTime detectedAt;
    private long fileSize;

    public ThreatRecord() {
    }

    public ThreatRecord(String filePath, String fileName, String fileHash,
                         ThreatType type, String threatName, long fileSize) {
        this.filePath = filePath;
        this.fileName = fileName;
        this.fileHash = fileHash;
        this.type = type;
        this.threatName = threatName;
        this.fileSize = fileSize;
        this.status = ThreatStatus.DETECTED;
        this.detectedAt = LocalDateTime.now();
    }

    // Getters et Setters
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getFileHash() {
        return fileHash;
    }

    public void setFileHash(String fileHash) {
        this.fileHash = fileHash;
    }

    public ThreatType getType() {
        return type;
    }

    public void setType(ThreatType type) {
        this.type = type;
    }

    public String getThreatName() {
        return threatName;
    }

    public void setThreatName(String threatName) {
        this.threatName = threatName;
    }

    public ThreatStatus getStatus() {
        return status;
    }

    public void setStatus(ThreatStatus status) {
        this.status = status;
    }

    public LocalDateTime getDetectedAt() {
        return detectedAt;
    }

    public void setDetectedAt(LocalDateTime detectedAt) {
        this.detectedAt = detectedAt;
    }

    public long getFileSize() {
        return fileSize;
    }

    public void setFileSize(long fileSize) {
        this.fileSize = fileSize;
    }

    @Override
    public String toString() {
        return "ThreatRecord{" +
                "fileName='" + fileName + '\'' +
                ", threatName='" + threatName + '\'' +
                ", type=" + type +
                ", status=" + status +
                ", detectedAt=" + detectedAt +
                '}';
    }
}
