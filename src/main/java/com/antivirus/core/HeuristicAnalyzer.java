package com.antivirus.core;

import com.antivirus.model.ThreatRecord;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Analyse heuristique : détecte les menaces potentielles SANS signature connue,
 * en se basant sur des règles (extensions suspectes, patterns de code, etc.)
 */
public class HeuristicAnalyzer {

    // Extensions considérées comme potentiellement dangereuses
    private static final List<String> SUSPICIOUS_EXTENSIONS = Arrays.asList(
            ".exe", ".bat", ".cmd", ".vbs", ".scr", ".jar", ".ps1", ".js", ".jse", ".wsf"
    );

    // Double extensions suspectes (ex: facture.pdf.exe)
    private static final Pattern DOUBLE_EXTENSION = Pattern.compile(
            "\\.(pdf|doc|docx|jpg|png|txt|xls|xlsx)\\.(exe|scr|bat|vbs|js)$",
            Pattern.CASE_INSENSITIVE
    );

    // Patterns de code suspect (pour fichiers texte/scripts)
    private static final List<Pattern> SUSPICIOUS_PATTERNS = Arrays.asList(
            Pattern.compile("eval\\s*\\(\\s*base64_decode", Pattern.CASE_INSENSITIVE),
            Pattern.compile("eval\\s*\\(\\s*atob", Pattern.CASE_INSENSITIVE),
            Pattern.compile("shell_exec\\s*\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("powershell\\s+-enc", Pattern.CASE_INSENSITIVE),
            Pattern.compile("powershell\\s+-encodedcommand", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Invoke-Expression", Pattern.CASE_INSENSITIVE),
            Pattern.compile("System\\.exit\\s*\\(\\s*0\\s*\\)\\s*;.*FormatC", Pattern.CASE_INSENSITIVE),
            Pattern.compile("rm\\s+-rf\\s+/", Pattern.CASE_INSENSITIVE),
            Pattern.compile("wget.*\\|.*sh", Pattern.CASE_INSENSITIVE),
            Pattern.compile("curl.*\\|.*bash", Pattern.CASE_INSENSITIVE)
    );

    private static final long MAX_FILE_SIZE_FOR_CONTENT_SCAN = 5 * 1024 * 1024; // 5 MB

    /**
     * Analyse un fichier de manière heuristique.
     * @return Un ThreatRecord si une menace potentielle est détectée, null sinon.
     */
    public ThreatRecord analyze(Path filePath, String fileHash) {
        String fileName = filePath.getFileName().toString();
        String fileNameLower = fileName.toLowerCase();

        // 1. Vérifier la double extension (technique de déguisement classique)
        if (DOUBLE_EXTENSION.matcher(fileNameLower).find()) {
            return createThreat(filePath, fileHash,
                    ThreatRecord.ThreatType.HEURISTIC_EXTENSION,
                    "Suspicious.DoubleExtension");
        }

        // 2. Vérifier le contenu pour les fichiers texte/scripts (taille raisonnable)
        try {
            long size = Files.size(filePath);
            if (size > 0 && size <= MAX_FILE_SIZE_FOR_CONTENT_SCAN && isTextLikeFile(fileNameLower)) {
                String matchedPattern = scanContent(filePath);
                if (matchedPattern != null) {
                    return createThreat(filePath, fileHash,
                            ThreatRecord.ThreatType.HEURISTIC_PATTERN,
                            "Suspicious.Pattern." + matchedPattern);
                }
            }
        } catch (IOException e) {
            // Fichier illisible, on ignore l'analyse de contenu
        }

        return null;
    }

    /**
     * Vérifie uniquement l'extension (utile pour scan rapide sans lire le contenu).
     */
    public boolean hasSuspiciousExtension(String fileName) {
        String lower = fileName.toLowerCase();
        return SUSPICIOUS_EXTENSIONS.stream().anyMatch(lower::endsWith);
    }

    private boolean isTextLikeFile(String fileNameLower) {
        return fileNameLower.endsWith(".php") || fileNameLower.endsWith(".js")
                || fileNameLower.endsWith(".sh") || fileNameLower.endsWith(".bat")
                || fileNameLower.endsWith(".ps1") || fileNameLower.endsWith(".vbs")
                || fileNameLower.endsWith(".py") || fileNameLower.endsWith(".txt")
                || fileNameLower.endsWith(".html") || fileNameLower.endsWith(".htm");
    }

    /**
     * Scanne le contenu d'un fichier ligne par ligne à la recherche de patterns suspects.
     * @return Le nom du pattern correspondant (court), ou null si aucun match.
     */
    private String scanContent(Path filePath) {
        try (BufferedReader reader = Files.newBufferedReader(filePath, StandardCharsets.UTF_8)) {
            String line;
            int lineNumber = 0;
            int maxLines = 5000; // limite pour éviter de scanner des fichiers énormes ligne par ligne

            while ((line = reader.readLine()) != null && lineNumber < maxLines) {
                for (Pattern pattern : SUSPICIOUS_PATTERNS) {
                    if (pattern.matcher(line).find()) {
                        return shortNameForPattern(pattern);
                    }
                }
                lineNumber++;
            }
        } catch (IOException e) {
            // Probablement un fichier binaire, on ignore
        }
        return null;
    }

    private String shortNameForPattern(Pattern pattern) {
        String p = pattern.pattern();
        if (p.contains("base64_decode") || p.contains("atob")) return "ObfuscatedCode";
        if (p.contains("shell_exec")) return "ShellExecution";
        if (p.contains("powershell")) return "EncodedPowershell";
        if (p.contains("Invoke-Expression")) return "InvokeExpression";
        if (p.contains("rm")) return "DestructiveCommand";
        if (p.contains("wget") || p.contains("curl")) return "RemoteDownloadExecute";
        return "GenericSuspicious";
    }

    private ThreatRecord createThreat(Path filePath, String fileHash,
                                       ThreatRecord.ThreatType type, String threatName) {
        long size;
        try {
            size = Files.size(filePath);
        } catch (IOException e) {
            size = 0;
        }
        return new ThreatRecord(
                filePath.toString(),
                filePath.getFileName().toString(),
                fileHash,
                type,
                threatName,
                size
        );
    }
}
