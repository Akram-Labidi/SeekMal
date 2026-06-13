package com.antivirus.core;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

/**
 * Gère la base de signatures connues (hash -> nom de la menace).
 * En production, ces signatures viendraient d'une base type ClamAV ou VirusShare.
 * Ici, on simule avec un fichier JSON local.
 */
public class SignatureDatabase {

    private Map<String, String> signatures; // hash -> nom de la menace
    private final String signaturesFilePath;

    public SignatureDatabase(String signaturesFilePath) {
        this.signaturesFilePath = signaturesFilePath;
        this.signatures = new HashMap<>();
        loadSignatures();
    }

    /**
     * Charge les signatures depuis le fichier JSON.
     * Format attendu : { "hash1": "Nom.Menace1", "hash2": "Nom.Menace2" }
     */
    public void loadSignatures() {
        try (FileReader reader = new FileReader(signaturesFilePath)) {
            Gson gson = new Gson();
            Type type = new TypeToken<Map<String, String>>() {}.getType();
            Map<String, String> loaded = gson.fromJson(reader, type);
            if (loaded != null) {
                signatures = loaded;
            }
            System.out.println("Signatures chargées : " + signatures.size());
        } catch (IOException e) {
            System.err.println("Impossible de charger les signatures, utilisation de la base par défaut: " + e.getMessage());
            loadDefaultSignatures();
        }
    }

    /**
     * Signatures de test par défaut (hashes de fichiers EICAR et exemples fictifs).
     * EICAR est le fichier de test antivirus standard, totalement inoffensif.
     */
    private void loadDefaultSignatures() {
        signatures = new HashMap<>();
        // Hash SHA-256 du fichier de test EICAR (standard de l'industrie)
        signatures.put("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0", "EICAR-Test-File");
        // Exemples fictifs pour démonstration
        signatures.put("44d88612fea8a8f36de82e1278abb02f", "Trojan.GenericTest");
        signatures.put("e1112134b6dcc01357afff9bdb968646", "Worm.SampleDemo");
    }

    /**
     * Vérifie si un hash correspond à une signature connue.
     * @return Le nom de la menace si trouvée, null sinon.
     */
    public String checkHash(String hash) {
        if (hash == null) return null;
        return signatures.get(hash.toLowerCase());
    }

    public int getSignatureCount() {
        return signatures.size();
    }

    public void addSignature(String hash, String threatName) {
        signatures.put(hash.toLowerCase(), threatName);
    }
}
