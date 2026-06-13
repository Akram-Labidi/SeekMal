package com.antivirus.quarantine;

import com.antivirus.model.ThreatRecord;

import java.io.IOException;
import java.nio.file.*;
import java.time.format.DateTimeFormatter;

/**
 * Gère la mise en quarantaine, la restauration et la suppression définitive
 * des fichiers détectés comme menaces.
 */
public class QuarantineManager {

    private final Path quarantineDir;
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    public QuarantineManager(String quarantineDirPath) {
        this.quarantineDir = Paths.get(quarantineDirPath);
        initQuarantineDir();
    }

    private void initQuarantineDir() {
        try {
            if (!Files.exists(quarantineDir)) {
                Files.createDirectories(quarantineDir);
            }
        } catch (IOException e) {
            System.err.println("Erreur création dossier quarantaine: " + e.getMessage());
        }
    }

    /**
     * Met un fichier en quarantaine : le déplace vers le dossier sécurisé
     * et stocke son chemin original dans un fichier métadonnées.
     *
     * @return le nouveau chemin (en quarantaine) si succès, null sinon.
     */
    public String quarantineFile(ThreatRecord threat) {
        Path sourcePath = Paths.get(threat.getFilePath());

        if (!Files.exists(sourcePath)) {
            return null;
        }

        try {
            // Nom unique en quarantaine : timestamp_nomOriginal.quarantine
            String timestamp = java.time.LocalDateTime.now().format(TIMESTAMP_FORMAT);
            String quarantineFileName = timestamp + "_" + threat.getFileName() + ".quarantine";
            Path destPath = quarantineDir.resolve(quarantineFileName);

            // Déplacer le fichier
            Files.move(sourcePath, destPath, StandardCopyOption.REPLACE_EXISTING);

            // Sauvegarder les métadonnées (chemin original) pour permettre la restauration
            Path metaPath = quarantineDir.resolve(quarantineFileName + ".meta");
            Files.writeString(metaPath, threat.getFilePath());

            return destPath.toString();

        } catch (IOException e) {
            System.err.println("Erreur mise en quarantaine: " + e.getMessage());
            return null;
        }
    }

    /**
     * Restaure un fichier de la quarantaine vers son emplacement original.
     */
    public boolean restoreFile(String quarantinePath) {
        Path quarantineFile = Paths.get(quarantinePath);
        Path metaPath = Paths.get(quarantinePath + ".meta");

        if (!Files.exists(quarantineFile) || !Files.exists(metaPath)) {
            return false;
        }

        try {
            String originalPath = Files.readString(metaPath).trim();
            Path destPath = Paths.get(originalPath);

            // Créer le dossier de destination s'il n'existe plus
            if (destPath.getParent() != null && !Files.exists(destPath.getParent())) {
                Files.createDirectories(destPath.getParent());
            }

            Files.move(quarantineFile, destPath, StandardCopyOption.REPLACE_EXISTING);
            Files.deleteIfExists(metaPath);

            return true;

        } catch (IOException e) {
            System.err.println("Erreur restauration: " + e.getMessage());
            return false;
        }
    }

    /**
     * Supprime définitivement un fichier en quarantaine.
     */
    public boolean deletePermanently(String quarantinePath) {
        try {
            Files.deleteIfExists(Paths.get(quarantinePath));
            Files.deleteIfExists(Paths.get(quarantinePath + ".meta"));
            return true;
        } catch (IOException e) {
            System.err.println("Erreur suppression: " + e.getMessage());
            return false;
        }
    }

    /**
     * Retourne le chemin du dossier de quarantaine.
     */
    public Path getQuarantineDir() {
        return quarantineDir;
    }

    /**
     * Calcule la taille totale occupée par la quarantaine (en octets).
     */
    public long getQuarantineSizeBytes() {
        try {
            return Files.walk(quarantineDir)
                    .filter(Files::isRegularFile)
                    .mapToLong(p -> {
                        try {
                            return Files.size(p);
                        } catch (IOException e) {
                            return 0L;
                        }
                    })
                    .sum();
        } catch (IOException e) {
            return 0L;
        }
    }
}
