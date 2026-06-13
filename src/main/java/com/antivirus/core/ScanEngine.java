package com.antivirus.core;

import com.antivirus.model.ScanResult;
import com.antivirus.model.ThreatRecord;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.function.Consumer;

/**
 * Moteur central de scan : parcourt fichiers/dossiers, calcule les hash,
 * vérifie les signatures et lance l'analyse heuristique.
 */
public class ScanEngine {

    private final SignatureDatabase signatureDatabase;
    private final HeuristicAnalyzer heuristicAnalyzer;

    private volatile boolean cancelled = false;

    public ScanEngine(SignatureDatabase signatureDatabase) {
        this.signatureDatabase = signatureDatabase;
        this.heuristicAnalyzer = new HeuristicAnalyzer();
    }

    /**
     * Annule un scan en cours.
     */
    public void cancel() {
        cancelled = true;
    }

    /**
     * Scan d'un dossier complet (récursif).
     *
     * @param targetPath chemin du dossier à scanner
     * @param scanType   type de scan (QUICK, FULL, CUSTOM)
     * @param onFileScanned callback appelé après chaque fichier (pour mise à jour UI/progress)
     * @param onThreatFound callback appelé dès qu'une menace est trouvée
     * @return le résultat complet du scan
     */
    public ScanResult scanDirectory(Path targetPath, ScanResult.ScanType scanType,
                                     Consumer<String> onFileScanned,
                                     Consumer<ThreatRecord> onThreatFound) {

        cancelled = false;
        ScanResult result = new ScanResult(scanType, targetPath.toString());

        try {
            Files.walkFileTree(targetPath, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (cancelled) {
                        return FileVisitResult.TERMINATE;
                    }

                    try {
                        ThreatRecord threat = scanFile(file);
                        result.incrementFilesScanned();

                        if (onFileScanned != null) {
                            onFileScanned.accept(file.toString());
                        }

                        if (threat != null) {
                            result.addThreat(threat);
                            if (onThreatFound != null) {
                                onThreatFound.accept(threat);
                            }
                        }
                    } catch (Exception e) {
                        // Fichier illisible/inaccessible, on continue
                    }

                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    // Fichier inaccessible (permissions, etc.), on continue
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            System.err.println("Erreur lors du scan: " + e.getMessage());
        }

        result.finish();
        return result;
    }

    /**
     * Scan d'un fichier unique.
     * @return ThreatRecord si une menace est détectée, null sinon.
     */
    public ThreatRecord scanFile(Path file) {
        if (!Files.isRegularFile(file)) {
            return null;
        }

        try {
            // 1. Calculer le hash du fichier (uniquement si pas trop gros pour rester rapide)
            long fileSize = Files.size(file);
            String hash = null;

            if (fileSize <= 50 * 1024 * 1024) { // 50 MB max pour le hashing
                hash = computeHash(file, "SHA-256");
            }

            // 2. Vérifier la signature
            if (hash != null) {
                String threatName = signatureDatabase.checkHash(hash);
                if (threatName != null) {
                    return new ThreatRecord(
                            file.toString(),
                            file.getFileName().toString(),
                            hash,
                            ThreatRecord.ThreatType.SIGNATURE_MATCH,
                            threatName,
                            fileSize
                    );
                }

                // Vérifier aussi avec MD5 (certaines bases utilisent MD5)
                String md5Hash = computeHash(file, "MD5");
                String threatNameMd5 = signatureDatabase.checkHash(md5Hash);
                if (threatNameMd5 != null) {
                    return new ThreatRecord(
                            file.toString(),
                            file.getFileName().toString(),
                            md5Hash,
                            ThreatRecord.ThreatType.SIGNATURE_MATCH,
                            threatNameMd5,
                            fileSize
                    );
                }
            }

            // 3. Analyse heuristique si pas de match par signature
            return heuristicAnalyzer.analyze(file, hash);

        } catch (IOException | NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * Calcule le hash d'un fichier selon l'algorithme spécifié (MD5, SHA-256, etc.)
     */
    public static String computeHash(Path file, String algorithm) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);

        try (var inputStream = Files.newInputStream(file)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }

        byte[] hashBytes = digest.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Compte le nombre total de fichiers dans un dossier (pour la barre de progression).
     */
    public static long countFiles(Path targetPath) {
        try {
            return Files.walk(targetPath)
                    .filter(Files::isRegularFile)
                    .count();
        } catch (IOException e) {
            return 0;
        }
    }
}
