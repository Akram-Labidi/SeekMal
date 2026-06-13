package com.antivirus.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

/**
 * Utilitaire pour le hachage des mots de passe avec SHA-256.
 */
public class PasswordHasher {

    /**
     * Hache un mot de passe avec SHA-256.
     * @param password Le mot de passe en clair
     * @return Le hash SHA-256 en hexadécimal
     */
    public static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            
            // Convertir le hash en hexadécimal
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    /**
     * Vérifie si un mot de passe correspond au hash stocké.
     * @param password Le mot de passe en clair
     * @param storedHash Le hash stocké
     * @return true si le mot de passe correspond
     */
    public static boolean verifyPassword(String password, String storedHash) {
        String computedHash = hashPassword(password);
        return computedHash.equals(storedHash);
    }
}
