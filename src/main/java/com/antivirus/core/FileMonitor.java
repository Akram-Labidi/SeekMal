package com.antivirus.core;

import com.antivirus.model.ThreatRecord;

import java.io.IOException;
import java.nio.file.*;
import java.util.function.Consumer;

/**
 * Surveille un dossier en temps réel et scanne chaque nouveau fichier
 * dès sa création (protection en temps réel).
 */
public class FileMonitor {

    private final ScanEngine scanEngine;
    private WatchService watchService;
    private Thread monitorThread;
    private volatile boolean running = false;

    public FileMonitor(ScanEngine scanEngine) {
        this.scanEngine = scanEngine;
    }

    /**
     * Démarre la surveillance d'un dossier.
     *
     * @param directory       dossier à surveiller
     * @param onNewFile       callback appelé pour chaque nouveau fichier détecté
     * @param onThreatFound   callback appelé si une menace est détectée
     * @param onStatusChange  callback pour informer l'UI du statut (démarrage/arrêt)
     */
    public void startMonitoring(Path directory,
                                 Consumer<String> onNewFile,
                                 Consumer<ThreatRecord> onThreatFound,
                                 Consumer<String> onStatusChange) {

        if (running) {
            return;
        }

        try {
            watchService = FileSystems.getDefault().newWatchService();
            directory.register(watchService,
                    StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_MODIFY);

            running = true;

            monitorThread = new Thread(() -> {
                if (onStatusChange != null) {
                    onStatusChange.accept("Surveillance active sur : " + directory);
                }

                while (running) {
                    WatchKey key;
                    try {
                        key = watchService.poll(1, java.util.concurrent.TimeUnit.SECONDS);
                        if (key == null) continue;
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    } catch (ClosedWatchServiceException e) {
                        break;
                    }

                    for (WatchEvent<?> event : key.pollEvents()) {
                        if (event.kind() == StandardWatchEventKinds.OVERFLOW) {
                            continue;
                        }

                        @SuppressWarnings("unchecked")
                        WatchEvent<Path> pathEvent = (WatchEvent<Path>) event;
                        Path fileName = pathEvent.context();
                        Path fullPath = directory.resolve(fileName);

                        if (onNewFile != null) {
                            onNewFile.accept(fullPath.toString());
                        }

                        // Scanner le fichier immédiatement
                        try {
                            if (Files.exists(fullPath) && Files.isRegularFile(fullPath)) {
                                // Petite pause pour laisser le temps au fichier d'être complètement écrit
                                Thread.sleep(200);
                                ThreatRecord threat = scanEngine.scanFile(fullPath);
                                if (threat != null && onThreatFound != null) {
                                    onThreatFound.accept(threat);
                                }
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        } catch (Exception e) {
                            // Fichier verrouillé ou supprimé entre-temps, on ignore
                        }
                    }

                    boolean valid = key.reset();
                    if (!valid) {
                        break;
                    }
                }

                if (onStatusChange != null) {
                    onStatusChange.accept("Surveillance arrêtée");
                }
            }, "FileMonitor-Thread");

            monitorThread.setDaemon(true);
            monitorThread.start();

        } catch (IOException e) {
            if (onStatusChange != null) {
                onStatusChange.accept("Erreur démarrage surveillance: " + e.getMessage());
            }
        }
    }

    /**
     * Arrête la surveillance.
     */
    public void stopMonitoring() {
        running = false;
        try {
            if (watchService != null) {
                watchService.close();
            }
        } catch (IOException e) {
            // Ignorer
        }
    }

    public boolean isRunning() {
        return running;
    }
}
