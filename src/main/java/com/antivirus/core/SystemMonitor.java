package com.antivirus.core;

import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.GlobalMemory;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.software.os.FileSystem;
import oshi.software.os.OSFileStore;
import oshi.software.os.OperatingSystem;

import java.util.List;

/**
 * Fournit les informations système (CPU, RAM, disque) pour le dashboard.
 */
public class SystemMonitor {

    private final SystemInfo systemInfo;
    private final HardwareAbstractionLayer hardware;
    private final CentralProcessor processor;
    private final GlobalMemory memory;
    private final OperatingSystem os;

    private long[] previousTicks;

    public SystemMonitor() {
        systemInfo = new SystemInfo();
        hardware = systemInfo.getHardware();
        processor = hardware.getProcessor();
        memory = hardware.getMemory();
        os = systemInfo.getOperatingSystem();
        previousTicks = processor.getSystemCpuLoadTicks();
    }

    /**
     * Retourne le pourcentage d'utilisation CPU global (0-100).
     */
    public double getCpuUsagePercent() {
        double load = processor.getSystemCpuLoadBetweenTicks(previousTicks);
        previousTicks = processor.getSystemCpuLoadTicks();
        return load * 100.0;
    }

    /**
     * Retourne le pourcentage d'utilisation RAM (0-100).
     */
    public double getMemoryUsagePercent() {
        long total = memory.getTotal();
        long available = memory.getAvailable();
        long used = total - available;
        if (total == 0) return 0;
        return (used * 100.0) / total;
    }

    public long getTotalMemoryBytes() {
        return memory.getTotal();
    }

    public long getUsedMemoryBytes() {
        return memory.getTotal() - memory.getAvailable();
    }

    /**
     * Retourne le pourcentage d'utilisation disque pour le disque principal.
     */
    public double getDiskUsagePercent() {
        FileSystem fileSystem = os.getFileSystem();
        List<OSFileStore> fileStores = fileSystem.getFileStores();

        if (fileStores.isEmpty()) return 0;

        // On prend le premier disque (ou celui avec le plus grand espace, racine système)
        OSFileStore mainStore = fileStores.get(0);
        long total = mainStore.getTotalSpace();
        long usable = mainStore.getUsableSpace();

        if (total == 0) return 0;
        return ((total - usable) * 100.0) / total;
    }

    public long getTotalDiskBytes() {
        List<OSFileStore> fileStores = os.getFileSystem().getFileStores();
        return fileStores.isEmpty() ? 0 : fileStores.get(0).getTotalSpace();
    }

    public long getFreeDiskBytes() {
        List<OSFileStore> fileStores = os.getFileSystem().getFileStores();
        return fileStores.isEmpty() ? 0 : fileStores.get(0).getUsableSpace();
    }

    /**
     * Formate des octets en chaîne lisible (KB, MB, GB).
     */
    public static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        String pre = "KMGTPE".charAt(exp - 1) + "";
        return String.format("%.2f %sB", bytes / Math.pow(1024, exp), pre);
    }
}
