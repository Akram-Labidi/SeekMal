package com.antivirus.ui;

import com.antivirus.core.*;
import com.antivirus.db.DatabaseManager;
import com.antivirus.model.ScanResult;
import com.antivirus.model.ThreatRecord;
import com.antivirus.quarantine.QuarantineManager;

import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


/**
 * Contrôleur principal : gère la navigation entre vues et toute la logique
 * (scan, quarantaine, monitoring temps réel, dashboard).
 */
public class DashboardController {

    // ---------- Sidebar ----------
    @FXML private Button navDashboard;
    @FXML private Button navScan;
    @FXML private Button navRealtime;
    @FXML private Button navQuarantine;
    @FXML private Button navHistory;
    @FXML private Button navChangePassword;
    @FXML private Label signatureCountLabel;

    // ---------- Header ----------
    @FXML private Label pageTitleLabel;
    @FXML private Label pageSubtitleLabel;
    @FXML private HBox globalStatusPill;
    @FXML private Circle globalStatusDot;
    @FXML private Label globalStatusLabel;

    // ---------- Views ----------
    @FXML private ScrollPane dashboardView;
    @FXML private VBox scanView;
    @FXML private VBox realtimeView;
    @FXML private VBox quarantineView;
    @FXML private VBox historyView;

    // ---------- Dashboard KPIs ----------
    @FXML private Label kpiTotalScans;
    @FXML private Label kpiFilesScanned;
    @FXML private Label kpiThreatsFound;
    @FXML private Label kpiQuarantined;

    // ---------- System resources ----------
    @FXML private ProgressBar cpuProgressBar;
    @FXML private ProgressBar memProgressBar;
    @FXML private ProgressBar diskProgressBar;
    @FXML private Label cpuValueLabel;
    @FXML private Label memValueLabel;
    @FXML private Label diskValueLabel;

    // ---------- Charts ----------
    @FXML private LineChart<String, Number> threatsLineChart;
    @FXML private PieChart threatTypePieChart;
    @FXML private ListView<String> activityLogList;

    // ---------- Scan view ----------
    @FXML private ComboBox<String> scanTypeCombo;
    @FXML private TextField scanPathField;
    @FXML private Button startScanButton;
    @FXML private Button cancelScanButton;
    @FXML private ProgressBar scanProgressBar;
    @FXML private Label scanStatusLabel;
    @FXML private Label scanCountLabel;
    @FXML private TableView<ThreatRecord> scanThreatsTable;
    @FXML private TableColumn<ThreatRecord, String> colScanFile;
    @FXML private TableColumn<ThreatRecord, String> colScanThreatName;
    @FXML private TableColumn<ThreatRecord, String> colScanType;
    @FXML private TableColumn<ThreatRecord, String> colScanHash;
    @FXML private TableColumn<ThreatRecord, Void> colScanAction;

    // ---------- Realtime view ----------
    @FXML private TextField monitorPathField;
    @FXML private Button startMonitorButton;
    @FXML private Button stopMonitorButton;
    @FXML private HBox monitorStatusPill;
    @FXML private Circle monitorStatusDot;
    @FXML private Label monitorStatusLabel;
    @FXML private ListView<String> realtimeLogList;

    // ---------- Quarantine view ----------
    @FXML private Label quarantinePathLabel;
    @FXML private Label quarantineSizeLabel;
    @FXML private TableView<ThreatRecord> quarantineTable;
    @FXML private TableColumn<ThreatRecord, String> colQFile;
    @FXML private TableColumn<ThreatRecord, String> colQThreat;
    @FXML private TableColumn<ThreatRecord, String> colQDate;
    @FXML private TableColumn<ThreatRecord, String> colQSize;
    @FXML private TableColumn<ThreatRecord, Void> colQActions;

    // ---------- History view ----------
    @FXML private TableView<ScanResult> historyTable;
    @FXML private TableColumn<ScanResult, String> colHType;
    @FXML private TableColumn<ScanResult, String> colHPath;
    @FXML private TableColumn<ScanResult, Number> colHFiles;
    @FXML private TableColumn<ScanResult, Number> colHThreats;
    @FXML private TableColumn<ScanResult, String> colHDuration;
    @FXML private TableColumn<ScanResult, String> colHDate;

    @FXML private TableView<ThreatRecord> allThreatsTable;
    @FXML private TableColumn<ThreatRecord, String> colATFile;
    @FXML private TableColumn<ThreatRecord, String> colATThreat;
    @FXML private TableColumn<ThreatRecord, String> colATType;
    @FXML private TableColumn<ThreatRecord, String> colATStatus;
    @FXML private TableColumn<ThreatRecord, String> colATDate;

    // ---------- Backend ----------
    private final DatabaseManager db = DatabaseManager.getInstance();
    private SignatureDatabase signatureDatabase;
    private ScanEngine scanEngine;
    private FileMonitor fileMonitor;
    private QuarantineManager quarantineManager;
    private SystemMonitor systemMonitor;
    private String currentUsername;

    private final ExecutorService executor = Executors.newFixedThreadPool(2);
    private Timeline systemMonitorTimeline;

    private static final DateTimeFormatter DISPLAY_FORMAT = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");

    private final ObservableList<ThreatRecord> currentScanThreats = FXCollections.observableArrayList();
    private final ObservableList<String> activityLog = FXCollections.observableArrayList();
    private final ObservableList<String> realtimeLog = FXCollections.observableArrayList();

    public void setCurrentUsername(String username) {
        this.currentUsername = username;
    }

    @FXML
    public void initialize() {
        // ---- Backend init ----
        String signaturesPath = resolveSignaturesPath();
        signatureDatabase = new SignatureDatabase(signaturesPath);
        scanEngine = new ScanEngine(signatureDatabase);
        fileMonitor = new FileMonitor(scanEngine);
        quarantineManager = new QuarantineManager("quarantine");
        systemMonitor = new SystemMonitor();

        signatureCountLabel.setText(signatureDatabase.getSignatureCount() + " entrées");
        quarantinePathLabel.setText(quarantineManager.getQuarantineDir().toAbsolutePath().toString());

        // ---- Combo scan types ----
        scanTypeCombo.setItems(FXCollections.observableArrayList(
                "Analyse rapide", "Analyse complète", "Analyse personnalisée"
        ));
        scanTypeCombo.getSelectionModel().selectFirst();

        // ---- Tables ----
        setupScanTable();
        setupQuarantineTable();
        setupHistoryTables();

        // ---- Lists ----
        activityLogList.setItems(activityLog);
        realtimeLogList.setItems(realtimeLog);

        // ---- System monitor refresh (every 2s) ----
        systemMonitorTimeline = new Timeline(new KeyFrame(Duration.seconds(2), e -> refreshSystemStats()));
        systemMonitorTimeline.setCycleCount(Timeline.INDEFINITE);
        systemMonitorTimeline.play();
        refreshSystemStats();

        // ---- Initial data load ----
        refreshDashboard();
        refreshQuarantineTable();
        refreshHistoryTables();

        addActivityLog("Application démarrée. " + signatureDatabase.getSignatureCount() + " signatures chargées.", LogLevel.INFO);
    }

    /**
     * Résout le chemin du fichier de signatures, qu'on soit en dev (resources) ou packagé.
     */
    private String resolveSignaturesPath() {
        // Tente d'abord le chemin de développement standard
        File devPath = new File("src/main/resources/signatures/signatures.json");
        if (devPath.exists()) {
            return devPath.getAbsolutePath();
        }
        // Sinon, extrait depuis le classpath vers un fichier temporaire
        try {
            var resourceStream = getClass().getResourceAsStream("/signatures/signatures.json");
            if (resourceStream != null) {
                File tempFile = File.createTempFile("signatures", ".json");
                tempFile.deleteOnExit();
                java.nio.file.Files.copy(resourceStream, tempFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                return tempFile.getAbsolutePath();
            }
        } catch (IOException e) {
            // ignore, fallback ci-dessous
        }
        return "signatures.json"; // SignatureDatabase utilisera ses signatures par défaut si absent
    }

    // ================================================================
    //  NAVIGATION
    // ================================================================

    @FXML
    private void showDashboardView() {
        setActiveView(dashboardView, navDashboard, "Tableau de bord", "Vue d'ensemble de la protection du système");
        refreshDashboard();
    }

    @FXML
    private void showScanView() {
        setActiveView(scanView, navScan, "Analyse", "Lancer un scan manuel et consulter les résultats");
    }

    @FXML
    private void showRealtimeView() {
        setActiveView(realtimeView, navRealtime, "Protection temps réel", "Surveillance active du système de fichiers");
    }

    @FXML
    private void showQuarantineView() {
        setActiveView(quarantineView, navQuarantine, "Quarantaine", "Gestion des fichiers isolés");
        refreshQuarantineTable();
    }

    @FXML
    private void showHistoryView() {
        setActiveView(historyView, navHistory, "Historique", "Historique des scans et menaces enregistrées");
        refreshHistoryTables();
    }

    @FXML
    private void showChangePasswordDialog() {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/fxml/change_password.fxml"));
            Parent root = loader.load();

            Stage dialogStage = new Stage();
            dialogStage.setTitle("Changer le mot de passe");
            dialogStage.initModality(Modality.APPLICATION_MODAL);
            
            Scene scene = new Scene(root);
            scene.getStylesheets().add(getClass().getResource("/css/style.css").toExternalForm());
            dialogStage.setScene(scene);
            dialogStage.setResizable(false);

            ChangePasswordController controller = loader.getController();
            controller.setUsername(currentUsername);
            controller.setStage(dialogStage);

            dialogStage.showAndWait();
        } catch (IOException e) {
            addActivityLog("Erreur lors de l'ouverture du dialogue de changement de mot de passe: " + e.getMessage(), LogLevel.INFO);
            e.printStackTrace();
        }
    }

    private void setActiveView(javafx.scene.Node view, Button activeNav, String title, String subtitle) {
        for (var v : new javafx.scene.Node[]{dashboardView, scanView, realtimeView, quarantineView, historyView}) {
            v.setVisible(v == view);
            v.setManaged(v == view);
        }
        for (Button b : new Button[]{navDashboard, navScan, navRealtime, navQuarantine, navHistory}) {
            b.getStyleClass().remove("nav-button-active");
        }
        activeNav.getStyleClass().add("nav-button-active");
        pageTitleLabel.setText(title);
        pageSubtitleLabel.setText(subtitle);
    }

    // ================================================================
    //  DASHBOARD
    // ================================================================

    private void refreshDashboard() {
        int totalScans = db.getTotalScansCount();
        int filesScanned = db.getTotalFilesScanned();
        int threatsFound = db.getTotalThreatsCount();
        int quarantined = db.getQuarantinedCount();

        kpiTotalScans.setText(String.valueOf(totalScans));
        kpiFilesScanned.setText(String.valueOf(filesScanned));
        kpiThreatsFound.setText(String.valueOf(threatsFound));
        kpiQuarantined.setText(String.valueOf(quarantined));

        updateGlobalStatus(threatsFound, quarantined);
        updateCharts();
    }

    private void updateGlobalStatus(int totalThreats, int quarantined) {
        int activeThreats = db.getAllThreats().stream()
                .filter(t -> t.getStatus() == ThreatRecord.ThreatStatus.DETECTED)
                .toList()
                .size();

        globalStatusPill.getStyleClass().removeAll("status-pill-ok", "status-pill-warning", "status-pill-danger");
        globalStatusDot.getStyleClass().removeAll("status-dot-ok", "status-dot-warning", "status-dot-danger");

        if (activeThreats > 0) {
            globalStatusPill.getStyleClass().add("status-pill-danger");
            globalStatusDot.getStyleClass().add("status-dot-danger");
            globalStatusLabel.setText(activeThreats + " MENACE(S) NON TRAITÉE(S)");
        } else if (quarantined > 0) {
            globalStatusPill.getStyleClass().add("status-pill-warning");
            globalStatusDot.getStyleClass().add("status-dot-warning");
            globalStatusLabel.setText(quarantined + " FICHIER(S) EN QUARANTAINE");
        } else {
            globalStatusPill.getStyleClass().add("status-pill-ok");
            globalStatusDot.getStyleClass().add("status-dot-ok");
            globalStatusLabel.setText("SYSTÈME PROTÉGÉ");
        }
    }

    private void updateCharts() {
        // Line chart : menaces par scan (historique)
        List<ScanResult> history = db.getScanHistory(15);
        XYChart.Series<String, Number> series = new XYChart.Series<>();
        // Inverser pour avoir l'ordre chronologique
        for (int i = history.size() - 1; i >= 0; i--) {
            ScanResult sr = history.get(i);
            series.getData().add(new XYChart.Data<>("#" + sr.getId(), sr.getThreatsFound()));
        }
        threatsLineChart.getData().clear();
        threatsLineChart.getData().add(series);

        // Pie chart : répartition par type de menace
        List<ThreatRecord> allThreats = db.getAllThreats();
        long sigCount = allThreats.stream().filter(t -> t.getType() == ThreatRecord.ThreatType.SIGNATURE_MATCH).count();
        long extCount = allThreats.stream().filter(t -> t.getType() == ThreatRecord.ThreatType.HEURISTIC_EXTENSION).count();
        long patCount = allThreats.stream().filter(t -> t.getType() == ThreatRecord.ThreatType.HEURISTIC_PATTERN).count();

        ObservableList<PieChart.Data> pieData = FXCollections.observableArrayList();
        if (sigCount > 0) pieData.add(new PieChart.Data("Signature (" + sigCount + ")", sigCount));
        if (extCount > 0) pieData.add(new PieChart.Data("Extension suspecte (" + extCount + ")", extCount));
        if (patCount > 0) pieData.add(new PieChart.Data("Pattern suspect (" + patCount + ")", patCount));
        if (pieData.isEmpty()) pieData.add(new PieChart.Data("Aucune menace", 1));

        threatTypePieChart.setData(pieData);
    }

    private void refreshSystemStats() {
        double cpu = systemMonitor.getCpuUsagePercent();
        double mem = systemMonitor.getMemoryUsagePercent();
        double disk = systemMonitor.getDiskUsagePercent();

        cpuProgressBar.setProgress(cpu / 100.0);
        memProgressBar.setProgress(mem / 100.0);
        diskProgressBar.setProgress(disk / 100.0);

        cpuValueLabel.setText(String.format("%.1f%%", cpu));
        memValueLabel.setText(String.format("%.1f%%", mem));
        diskValueLabel.setText(String.format("%.1f%%", disk));

        applyProgressBarStyle(cpuProgressBar, cpu);
        applyProgressBarStyle(memProgressBar, mem);
        applyProgressBarStyle(diskProgressBar, disk);
    }

    private void applyProgressBarStyle(ProgressBar bar, double value) {
        bar.getStyleClass().removeAll("progress-bar-warning", "progress-bar-danger");
        if (value >= 90) {
            bar.getStyleClass().add("progress-bar-danger");
        } else if (value >= 70) {
            bar.getStyleClass().add("progress-bar-warning");
        }
    }

    // ================================================================
    //  SCAN
    // ================================================================

    private void setupScanTable() {
        colScanFile.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(c.getValue().getFilePath()));
        colScanThreatName.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(c.getValue().getThreatName()));
        colScanType.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(typeLabel(c.getValue().getType())));
        colScanType.setCellFactory(col -> typeTagCell());
        colScanHash.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(
                c.getValue().getFileHash() != null ? c.getValue().getFileHash() : "—"));
        colScanHash.setCellFactory(col -> monoCell());

        colScanAction.setCellFactory(col -> new TableCell<>() {
            private final Button quarantineBtn = new Button("Mettre en quarantaine");
            {
                quarantineBtn.getStyleClass().addAll("btn-secondary", "btn-small");
                quarantineBtn.setOnAction(e -> {
                    ThreatRecord threat = getTableView().getItems().get(getIndex());
                    quarantineThreat(threat, scanThreatsTable);
                });
            }
            @Override
            protected void updateItem(Void item, boolean empty) {
                super.updateItem(item, empty);
                if (empty) {
                    setGraphic(null);
                } else {
                    ThreatRecord t = getTableView().getItems().get(getIndex());
                    quarantineBtn.setDisable(t.getStatus() != ThreatRecord.ThreatStatus.DETECTED);
                    quarantineBtn.setText(t.getStatus() == ThreatRecord.ThreatStatus.DETECTED
                            ? "Mettre en quarantaine" : "Déjà traité");
                    setGraphic(quarantineBtn);
                }
            }
        });

        scanThreatsTable.setItems(currentScanThreats);
        scanThreatsTable.setPlaceholder(new Label("Aucune menace détectée pour le moment."));
    }

    @FXML
    private void handleBrowseFolder() {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Sélectionner le dossier à scanner");
        File selected = chooser.showDialog(scanPathField.getScene().getWindow());
        if (selected != null) {
            scanPathField.setText(selected.getAbsolutePath());
        }
    }

    @FXML
    private void handleStartScan() {
        String pathStr = scanPathField.getText();
        if (pathStr == null || pathStr.isBlank()) {
            scanStatusLabel.setText("⚠ Veuillez sélectionner un dossier à scanner.");
            return;
        }

        Path targetPath = Paths.get(pathStr);
        if (!java.nio.file.Files.exists(targetPath)) {
            scanStatusLabel.setText("⚠ Le chemin spécifié n'existe pas.");
            return;
        }

        ScanResult.ScanType scanType = switch (scanTypeCombo.getValue()) {
            case "Analyse complète" -> ScanResult.ScanType.FULL_SCAN;
            case "Analyse personnalisée" -> ScanResult.ScanType.CUSTOM_SCAN;
            default -> ScanResult.ScanType.QUICK_SCAN;
        };

        currentScanThreats.clear();
        startScanButton.setDisable(true);
        cancelScanButton.setDisable(false);
        scanProgressBar.setProgress(0);
        scanStatusLabel.setText("Préparation du scan...");
        addActivityLog("Scan démarré : " + pathStr, LogLevel.ACTION);

        executor.submit(() -> {
            long totalFiles = ScanEngine.countFiles(targetPath);
            long[] scannedCount = {0};

            ScanResult result = scanEngine.scanDirectory(targetPath, scanType,
                    filePath -> {
                        scannedCount[0]++;
                        if (totalFiles > 0) {
                            double progress = (double) scannedCount[0] / totalFiles;
                            Platform.runLater(() -> {
                                scanProgressBar.setProgress(progress);
                                scanStatusLabel.setText("Analyse : " + truncatePath(filePath));
                                scanCountLabel.setText(scannedCount[0] + " / " + totalFiles + " fichiers");
                            });
                        }
                    },
                    threat -> Platform.runLater(() -> {
                        currentScanThreats.add(threat);
                        addActivityLog("Menace détectée : " + threat.getThreatName() + " — " + threat.getFileName(), LogLevel.THREAT);
                    })
            );

            Platform.runLater(() -> {
                db.saveScanResult(result);
                startScanButton.setDisable(false);
                cancelScanButton.setDisable(true);
                scanProgressBar.setProgress(1.0);
                scanStatusLabel.setText("Scan terminé : " + result.getFilesScanned() + " fichier(s) analysé(s), "
                        + result.getThreatsFound() + " menace(s) trouvée(s).");
                scanCountLabel.setText("");
                addActivityLog("Scan terminé : " + result.getThreatsFound() + " menace(s) sur " + result.getFilesScanned() + " fichiers.", LogLevel.INFO);
                refreshDashboard();
                refreshHistoryTables();
                // Recharger les statuts (au cas où des menaces ont été mises en quarantaine entre temps)
                scanThreatsTable.refresh();
            });
        });
    }

    @FXML
    private void handleCancelScan() {
        scanEngine.cancel();
        scanStatusLabel.setText("Annulation en cours...");
        cancelScanButton.setDisable(true);
    }

    @FXML
    private void handleExportReport() {
        if (currentScanThreats.isEmpty()) {
            scanStatusLabel.setText("Aucune menace à exporter.");
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Exporter le rapport");
        fileChooser.setInitialFileName("rapport_scan.csv");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV", "*.csv"));
        File file = fileChooser.showSaveDialog(scanPathField.getScene().getWindow());

        if (file != null) {
            try (FileWriter writer = new FileWriter(file)) {
                writer.write("Fichier,Menace,Type,Hash,Statut,Date détection\n");
                for (ThreatRecord t : currentScanThreats) {
                    writer.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                            t.getFilePath(), t.getThreatName(), typeLabel(t.getType()),
                            t.getFileHash() != null ? t.getFileHash() : "",
                            t.getStatus(), t.getDetectedAt().format(DISPLAY_FORMAT)));
                }
                scanStatusLabel.setText("Rapport exporté : " + file.getName());
                addActivityLog("Rapport exporté : " + file.getName(), LogLevel.ACTION);
            } catch (IOException e) {
                scanStatusLabel.setText("Erreur export : " + e.getMessage());
            }
        }
    }

    // ================================================================
    //  PROTECTION TEMPS RÉEL
    // ================================================================

    @FXML
    private void handleBrowseMonitorFolder() {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Sélectionner le dossier à surveiller");
        File selected = chooser.showDialog(monitorPathField.getScene().getWindow());
        if (selected != null) {
            monitorPathField.setText(selected.getAbsolutePath());
        }
    }

    @FXML
    private void handleStartMonitoring() {
        String pathStr = monitorPathField.getText();
        if (pathStr == null || pathStr.isBlank()) {
            addRealtimeLog("⚠ Veuillez sélectionner un dossier à surveiller.", LogLevel.INFO);
            return;
        }

        Path dir = Paths.get(pathStr);
        if (!java.nio.file.Files.isDirectory(dir)) {
            addRealtimeLog("⚠ Le chemin spécifié n'est pas un dossier valide.", LogLevel.INFO);
            return;
        }

        fileMonitor.startMonitoring(dir,
                newFile -> Platform.runLater(() ->
                        addRealtimeLog("Nouveau fichier détecté : " + truncatePath(newFile), LogLevel.INFO)),
                threat -> Platform.runLater(() -> {
                    addRealtimeLog("⚠ MENACE DÉTECTÉE : " + threat.getThreatName() + " — " + threat.getFileName(), LogLevel.THREAT);
                    // Enregistrer comme un mini scan REALTIME
                    ScanResult realtimeResult = new ScanResult(ScanResult.ScanType.REALTIME, dir.toString());
                    realtimeResult.incrementFilesScanned();
                    realtimeResult.addThreat(threat);
                    realtimeResult.finish();
                    db.saveScanResult(realtimeResult);
                    refreshDashboard();
                    addActivityLog("Protection temps réel : menace bloquée — " + threat.getFileName(), LogLevel.THREAT);
                }),
                status -> Platform.runLater(() -> {
                    addRealtimeLog(status, LogLevel.ACTION);
                    boolean active = fileMonitor.isRunning();
                    updateMonitorStatus(active);
                })
        );

        startMonitorButton.setDisable(true);
        stopMonitorButton.setDisable(false);
        updateMonitorStatus(true);
    }

    @FXML
    private void handleStopMonitoring() {
        fileMonitor.stopMonitoring();
        startMonitorButton.setDisable(false);
        stopMonitorButton.setDisable(true);
        updateMonitorStatus(false);
    }

    private void updateMonitorStatus(boolean active) {
        monitorStatusPill.getStyleClass().removeAll("status-pill-ok", "status-pill-warning");
        monitorStatusDot.getStyleClass().removeAll("status-dot-ok", "status-dot-warning");
        if (active) {
            monitorStatusPill.getStyleClass().add("status-pill-ok");
            monitorStatusDot.getStyleClass().add("status-dot-ok");
            monitorStatusLabel.setText("ACTIF");
        } else {
            monitorStatusPill.getStyleClass().add("status-pill-warning");
            monitorStatusDot.getStyleClass().add("status-dot-warning");
            monitorStatusLabel.setText("INACTIF");
        }
    }

    // ================================================================
    //  QUARANTAINE
    // ================================================================

    private void setupQuarantineTable() {
        colQFile.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(c.getValue().getFilePath()));
        colQThreat.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(c.getValue().getThreatName()));
        colQDate.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(c.getValue().getDetectedAt().format(DISPLAY_FORMAT)));
        colQDate.setCellFactory(col -> monoCell());
        colQSize.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(SystemMonitor.formatBytes(c.getValue().getFileSize())));
        colQSize.setCellFactory(col -> monoCell());

        colQActions.setCellFactory(col -> new TableCell<>() {
            private final Button restoreBtn = new Button("Restaurer");
            private final Button deleteBtn = new Button("Supprimer définitivement");
            private final HBox box = new HBox(8, restoreBtn, deleteBtn);
            {
                restoreBtn.getStyleClass().addAll("btn-secondary", "btn-small");
                deleteBtn.getStyleClass().addAll("btn-danger", "btn-small");

                restoreBtn.setOnAction(e -> {
                    ThreatRecord t = getTableView().getItems().get(getIndex());
                    String quarantinePath = quarantinePathFor(t);
                    if (quarantineManager.restoreFile(quarantinePath)) {
                        db.updateThreatStatus(t.getId(), ThreatRecord.ThreatStatus.RESTORED);
                        addActivityLog("Fichier restauré : " + t.getFileName(), LogLevel.ACTION);
                        refreshQuarantineTable();
                        refreshDashboard();
                        refreshHistoryTables();
                    }
                });

                deleteBtn.setOnAction(e -> {
                    ThreatRecord t = getTableView().getItems().get(getIndex());
                    String quarantinePath = quarantinePathFor(t);
                    if (quarantineManager.deletePermanently(quarantinePath)) {
                        db.updateThreatStatus(t.getId(), ThreatRecord.ThreatStatus.DELETED);
                        addActivityLog("Fichier supprimé définitivement : " + t.getFileName(), LogLevel.ACTION);
                        refreshQuarantineTable();
                        refreshDashboard();
                        refreshHistoryTables();
                    }
                });
            }
            @Override
            protected void updateItem(Void item, boolean empty) {
                super.updateItem(item, empty);
                setGraphic(empty ? null : box);
            }
        });

        quarantineTable.setPlaceholder(new Label("Aucun fichier en quarantaine."));
    }

    /**
     * Reconstruit le chemin de quarantaine à partir des métadonnées (best effort).
     * Note : pour une implémentation robuste, le chemin de quarantaine devrait être
     * stocké directement en base de données. Ici on recherche dans le dossier quarantaine
     * un fichier correspondant au nom original.
     */
    private String quarantinePathFor(ThreatRecord t) {
        try {
            return java.nio.file.Files.list(quarantineManager.getQuarantineDir())
                    .filter(p -> p.getFileName().toString().endsWith(t.getFileName() + ".quarantine"))
                    .findFirst()
                    .map(Path::toString)
                    .orElse("");
        } catch (IOException e) {
            return "";
        }
    }

    private void refreshQuarantineTable() {
        quarantineTable.setItems(FXCollections.observableArrayList(db.getQuarantinedThreats()));
        quarantineSizeLabel.setText(SystemMonitor.formatBytes(quarantineManager.getQuarantineSizeBytes()));
    }

    @FXML
    private void handleRefreshQuarantine() {
        refreshQuarantineTable();
    }

    /**
     * Met une menace en quarantaine et met à jour l'UI + la base de données.
     */
    private void quarantineThreat(ThreatRecord threat, TableView<ThreatRecord> sourceTable) {
        String newPath = quarantineManager.quarantineFile(threat);
        if (newPath != null) {
            threat.setStatus(ThreatRecord.ThreatStatus.QUARANTINED);
            if (threat.getId() != 0) {
                db.updateThreatStatus(threat.getId(), ThreatRecord.ThreatStatus.QUARANTINED);
            }
            addActivityLog("Fichier mis en quarantaine : " + threat.getFileName(), LogLevel.ACTION);
            sourceTable.refresh();
            refreshDashboard();
            refreshQuarantineTable();
            refreshHistoryTables();
        } else {
            addActivityLog("Échec mise en quarantaine : " + threat.getFileName(), LogLevel.THREAT);
        }
    }

    // ================================================================
    //  HISTORIQUE
    // ================================================================

    private void setupHistoryTables() {
        colHType.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(scanTypeLabel(c.getValue().getScanType())));
        colHPath.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(c.getValue().getTargetPath()));
        colHPath.setCellFactory(col -> monoCell());
        colHFiles.setCellValueFactory(c -> new javafx.beans.property.SimpleIntegerProperty(c.getValue().getFilesScanned()));
        colHThreats.setCellValueFactory(c -> new javafx.beans.property.SimpleIntegerProperty(c.getValue().getThreatsFound()));
        colHDuration.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(c.getValue().getDurationSeconds() + " s"));
        colHDuration.setCellFactory(col -> monoCell());
        colHDate.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(c.getValue().getStartTime().format(DISPLAY_FORMAT)));
        colHDate.setCellFactory(col -> monoCell());

        historyTable.setPlaceholder(new Label("Aucun scan effectué."));

        colATFile.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(c.getValue().getFilePath()));
        colATFile.setCellFactory(col -> monoCell());
        colATThreat.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(c.getValue().getThreatName()));
        colATType.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(typeLabel(c.getValue().getType())));
        colATType.setCellFactory(col -> typeTagCell());
        colATStatus.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(statusLabel(c.getValue().getStatus())));
        colATStatus.setCellFactory(col -> statusTagCell());
        colATDate.setCellValueFactory(c -> new javafx.beans.property.SimpleStringProperty(c.getValue().getDetectedAt().format(DISPLAY_FORMAT)));
        colATDate.setCellFactory(col -> monoCell());

        allThreatsTable.setPlaceholder(new Label("Aucune menace enregistrée."));
    }

    private void refreshHistoryTables() {
        historyTable.setItems(FXCollections.observableArrayList(db.getScanHistory(50)));
        allThreatsTable.setItems(FXCollections.observableArrayList(db.getAllThreats()));
    }

    // ================================================================
    //  HELPERS
    // ================================================================

    private enum LogLevel { INFO, THREAT, ACTION }

    private void addActivityLog(String message, LogLevel level) {
        String timestamp = java.time.LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        String prefix = switch (level) {
            case THREAT -> "[ALERTE] ";
            case ACTION -> "[ACTION] ";
            default -> "[INFO]   ";
        };
        activityLog.add(0, timestamp + "  " + prefix + message);
        if (activityLog.size() > 100) {
            activityLog.remove(activityLog.size() - 1);
        }
    }

    private void addRealtimeLog(String message, LogLevel level) {
        String timestamp = java.time.LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        String prefix = switch (level) {
            case THREAT -> "[ALERTE] ";
            case ACTION -> "[SYSTÈME] ";
            default -> "[EVENT]  ";
        };
        realtimeLog.add(0, timestamp + "  " + prefix + message);
        if (realtimeLog.size() > 200) {
            realtimeLog.remove(realtimeLog.size() - 1);
        }
    }

    private String truncatePath(String path) {
        if (path.length() <= 70) return path;
        return "..." + path.substring(path.length() - 67);
    }

    private String typeLabel(ThreatRecord.ThreatType type) {
        return switch (type) {
            case SIGNATURE_MATCH -> "Signature";
            case HEURISTIC_EXTENSION -> "Extension suspecte";
            case HEURISTIC_PATTERN -> "Pattern suspect";
            default -> "Inconnu";
        };
    }

    private String statusLabel(ThreatRecord.ThreatStatus status) {
        return switch (status) {
            case DETECTED -> "Détecté";
            case QUARANTINED -> "En quarantaine";
            case RESTORED -> "Restauré";
            case DELETED -> "Supprimé";
            case IGNORED -> "Ignoré";
        };
    }

    private String scanTypeLabel(ScanResult.ScanType type) {
        return switch (type) {
            case QUICK_SCAN -> "Rapide";
            case FULL_SCAN -> "Complet";
            case CUSTOM_SCAN -> "Personnalisé";
            case REALTIME -> "Temps réel";
        };
    }

    private <T> TableCell<T, String> monoCell() {
        return new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);

                if (empty || item == null) {
                    setText(null);
                    getStyleClass().remove("cell-mono");
                } else {
                    setText(item);
                    if (!getStyleClass().contains("cell-mono")) {
                        getStyleClass().add("cell-mono");
                    }
                }
            }
        };
    }

    private TableCell<ThreatRecord, String> typeTagCell() {
        return new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                getStyleClass().removeAll("tag-signature", "tag-heuristic");
                if (empty || item == null) {
                    setText(null);
                } else {
                    setText(item);
                    if (item.equals("Signature")) {
                        getStyleClass().add("tag-signature");
                    } else {
                        getStyleClass().add("tag-heuristic");
                    }
                }
            }
        };
    }

    private TableCell<ThreatRecord, String> statusTagCell() {
        return new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                getStyleClass().removeAll("tag-status-quarantined", "tag-status-detected",
                        "tag-status-restored", "tag-status-deleted");
                if (empty || item == null) {
                    setText(null);
                } else {
                    setText(item);
                    switch (item) {
                        case "En quarantaine" -> getStyleClass().add("tag-status-quarantined");
                        case "Détecté" -> getStyleClass().add("tag-status-detected");
                        case "Restauré" -> getStyleClass().add("tag-status-restored");
                        case "Supprimé" -> getStyleClass().add("tag-status-deleted");
                        default -> {}
                    }
                }
            }
        };
    }

    /**
     * Arrêt propre des threads (appelé à la fermeture de l'application).
     */
    public void shutdown() {
        fileMonitor.stopMonitoring();
        if (systemMonitorTimeline != null) {
            systemMonitorTimeline.stop();
        }
        executor.shutdownNow();
    }
}
