<<<<<<< HEAD
# SeekMal — Antivirus & Monitoring System

![Java](https://img.shields.io/badge/Java-17-orange)
![JavaFX](https://img.shields.io/badge/JavaFX-17.0.6-blue)
![License](https://img.shields.io/badge/License-MIT-green)

SeekMal est une application desktop JavaFX complète de protection antivirus et de surveillance système avec authentification sécurisée, base de données SQLite et interface moderne.

## 🚀 Fonctionnalités

### 🔐 Authentification & Sécurité
- **Système de login** avec username/password
- **Chiffrement SHA-256** pour les mots de passe
- **Changement de mot de passe** via interface sécurisée
- **Utilisateur par défaut**: admin / admin123@

### 🛡️ Scan de fichiers
- **3 modes de scan**: Rapide, Complet, Personnalisé
- **Détection par signature**: Comparaison SHA-256/MD5 avec base de signatures
- **Analyse heuristique**: Détection de patterns suspects
- **Barre de progression** en temps réel
- **Actions rapides**: Quarantaine, suppression, restauration
- **Export CSV** des rapports de scan

### ⚡ Protection temps réel
- **Surveillance de dossier** avec WatchService
- **Scan automatique** des nouveaux fichiers
- **Alertes immédiates** des menaces détectées
- **Journal d'événements** en direct

### 📊 Dashboard
- **KPIs**: Scans, fichiers analysés, menaces, quarantaine
- **Graphiques**: Évolution des menaces (LineChart), répartition (PieChart)
- **Monitoring système**: CPU, RAM, Disque en temps réel
- **Journal d'activité** avec logs colorés

### 🗃️ Quarantaine
- **Isolement sécurisé** des fichiers infectés
- **Restauration** vers l'emplacement original
- **Suppression définitive** des menaces
- **Historique** avec métadonnées

### 📜 Historique
- **Historique complet** des scans
- **Liste des menaces** avec statuts
- **Filtrage** par type et date

## 🛠️ Stack technique

| Technologie | Version | Usage |
|-------------|---------|-------|
| Java | 17+ | Langage principal |
| JavaFX | 17.0.6 | Interface utilisateur |
| SQLite | 3.43.0.0 | Base de données |
| OSHI | 6.4.6 | Monitoring système |
| Gson | 2.10.1 | JSON parsing |
| iText | 7.2.5 | Export PDF |
| Maven | - | Build management |

## 📦 Installation

### Prérequis
- JDK 17 ou supérieur (`java -version`)
- Maven installé (`mvn -version`)
- Connexion internet (premier build)

### Lancement

```bash
# Cloner le repository
git clone <repository-url>
cd antivirus-project

# Compiler et lancer
mvn clean javafx:run
```

### Configuration IDE (IntelliJ IDEA)

Ajoutez ces options VM dans la configuration de run:
```
--module-path %USERPROFILE%\.m2\repository\org\openjfx\javafx-controls\17.0.6;%USERPROFILE%\.m2\repository\org\openjfx\javafx-fxml\17.0.6;%USERPROFILE%\.m2\repository\org\openjfx\javafx-graphics\17.0.6;%USERPROFILE%\.m2\repository\org\openjfx\javafx-base\17.0.6 --add-modules javafx.controls,javafx.fxml
```

## 📁 Structure du projet

```
antivirus-project/
├── pom.xml
└── src/main/
    ├── java/com/antivirus/
    │   ├── MainApp.java                    # Point d'entrée
    │   ├── core/
    │   │   ├── ScanEngine.java             # Moteur de scan
    │   │   ├── SignatureDatabase.java      # Base de signatures
    │   │   ├── HeuristicAnalyzer.java      # Analyse heuristique
    │   │   ├── FileMonitor.java            # Surveillance temps réel
    │   │   └── SystemMonitor.java          # Monitoring système
    │   ├── db/
    │   │   └── DatabaseManager.java        # Gestion SQLite
    │   ├── model/
    │   │   ├── ScanResult.java
    │   │   └── ThreatRecord.java
    │   ├── quarantine/
    │   │   └── QuarantineManager.java      # Gestion quarantaine
    │   ├── ui/
    │   │   ├── DashboardController.java    # Contrôleur principal
    │   │   ├── LoginController.java        # Authentification
    │   │   └── ChangePasswordController.java # Changement mot de passe
    │   └── util/
    │       └── PasswordHasher.java         # Hachage SHA-256
    └── resources/
        ├── fxml/
        │   ├── dashboard.fxml              # Interface principale
        │   ├── login.fxml                  # Écran de connexion
        │   └── change_password.fxml         # Dialogue changement mot de passe
        ├── css/
        │   └── style.css                   # Thème sombre
        └── signatures/
            └── signatures.json              # Signatures de menaces
```

## 🔑 Identifiants par défaut

```
Username: admin
Password: admin123@
```

⚠️ **Important**: Changez le mot de passe après le premier lancement via le menu "Changer mot de passe" dans le dashboard.

## 🧪 Tester la détection

### Test EICAR (Fichier de test standard)

1. Créez un fichier texte contenant exactement:
   ```
   X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
   ```
2. Lancez un scan sur le dossier contenant ce fichier
3. SeekMal doit détecter "EICAR-Test-File"

### Test heuristique

Créez un fichier avec:
- Extension double: `document.pdf.exe`
- Pattern suspect: fichier `.php` contenant `eval(base64_decode(...))`

## 🗄️ Base de données

Au premier lancement, SeekMal crée automatiquement:
- `antivirus.db` - Base SQLite avec tables:
  - `scans` - Historique des scans
  - `threats` - Menaces détectées
  - `users` - Utilisateurs authentifiés
- `quarantine/` - Dossier d'isolement

## 🎨 Personnalisation

### Ajouter des signatures

Éditez `src/main/resources/signatures/signatures.json`:

```json
{
  "signatures": [
    {
      "hash": "sha256_hash_here",
      "name": "Nom de la menace",
      "type": "malware"
    }
  ]
}
```



## 📄 License

Ce projet est fourni à des fins éducatives.

---

**Note**: SeekMal est un projet éducatif. Pour une protection professionnelle, utilisez des solutions antivirus certifiées.
=======
# SeekMal
SeekMal — Système antivirus et monitoring desktop en JavaFX avec authentification sécurisée, scan de fichiers, protection temps réel, quarantaine et dashboard de surveillance.
>>>>>>> fb36993b6e4ae026d9283d54c4b1257c43cdba38
