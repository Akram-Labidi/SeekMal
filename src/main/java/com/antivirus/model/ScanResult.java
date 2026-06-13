package com.antivirus.model;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Représente le résultat global d'un scan (dossier ou fichier unique).
 */
public class ScanResult {

    public enum ScanType {
        QUICK_SCAN,
        FULL_SCAN,
        CUSTOM_SCAN,
        REALTIME
    }

    private int id;
    private ScanType scanType;
    private String targetPath;
    private int filesScanned;
    private int threatsFound;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private List<ThreatRecord> threats;

    public ScanResult(ScanType scanType, String targetPath) {
        this.scanType = scanType;
        this.targetPath = targetPath;
        this.filesScanned = 0;
        this.threatsFound = 0;
        this.startTime = LocalDateTime.now();
        this.threats = new ArrayList<>();
    }

    public void addThreat(ThreatRecord threat) {
        threats.add(threat);
        threatsFound++;
    }

    public void incrementFilesScanned() {
        filesScanned++;
    }

    public void finish() {
        this.endTime = LocalDateTime.now();
    }

    public long getDurationSeconds() {
        if (endTime == null) return 0;
        return java.time.Duration.between(startTime, endTime).getSeconds();
    }

    // Getters et Setters
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public ScanType getScanType() {
        return scanType;
    }

    public void setScanType(ScanType scanType) {
        this.scanType = scanType;
    }

    public String getTargetPath() {
        return targetPath;
    }

    public void setTargetPath(String targetPath) {
        this.targetPath = targetPath;
    }

    public int getFilesScanned() {
        return filesScanned;
    }

    public void setFilesScanned(int filesScanned) {
        this.filesScanned = filesScanned;
    }

    public int getThreatsFound() {
        return threatsFound;
    }

    public void setThreatsFound(int threatsFound) {
        this.threatsFound = threatsFound;
    }

    public LocalDateTime getStartTime() {
        return startTime;
    }

    public void setStartTime(LocalDateTime startTime) {
        this.startTime = startTime;
    }

    public LocalDateTime getEndTime() {
        return endTime;
    }

    public void setEndTime(LocalDateTime endTime) {
        this.endTime = endTime;
    }

    public List<ThreatRecord> getThreats() {
        return threats;
    }

    public void setThreats(List<ThreatRecord> threats) {
        this.threats = threats;
    }
}
