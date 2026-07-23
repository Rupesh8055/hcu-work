<?php

/**
 * ProfileTracker — lightweight runtime performance profiler.
 *
 * Tracks:
 *  - Wall-clock execution time of any labelled block
 *  - Peak PHP memory consumption
 *  - Slow database queries (>200 ms threshold by default)
 *
 * All telemetry is written to logs/profile_telemetry.log without
 * any external dependencies.  Designed to be zero-overhead: every
 * method fails silently if the log directory is not writable.
 */
class ProfileTracker {

    /** Absolute path to the telemetry log file */
    private static string $logFile = '';

    /** In-flight timer registry  [label => microtime start] */
    private static array $timers = [];

    /** Slow-query threshold in milliseconds */
    private static int $slowQueryMs = 200;

    // ------------------------------------------------------------------ //
    //  Boot
    // ------------------------------------------------------------------ //

    /**
     * Resolve the log file path once per process.
     */
    private static function logPath(): string {
        if (self::$logFile === '') {
            $logDir = defined('TOOLS_ROOT')
                ? TOOLS_ROOT . '/logs'
                : dirname(dirname(__DIR__)) . '/logs';

            if (!is_dir($logDir)) {
                @mkdir($logDir, 0755, true);
            }
            self::$logFile = $logDir . '/profile_telemetry.log';
        }
        return self::$logFile;
    }

    // ------------------------------------------------------------------ //
    //  Timer API
    // ------------------------------------------------------------------ //

    /**
     * Start a named timer.
     *
     * @param string $label  Human-readable name for this block.
     */
    public static function start(string $label): void {
        self::$timers[$label] = microtime(true);
    }

    /**
     * Stop a named timer and emit a telemetry line.
     *
     * @param string $label  Must match the label passed to start().
     * @return float         Elapsed time in milliseconds, or -1 on error.
     */
    public static function stop(string $label): float {
        if (!isset(self::$timers[$label])) {
            return -1.0;
        }

        $elapsedMs = (microtime(true) - self::$timers[$label]) * 1000.0;
        unset(self::$timers[$label]);

        $peakMb    = round(memory_get_peak_usage(true) / 1048576, 2);
        $suffix    = $elapsedMs > self::$slowQueryMs ? ' [SLOW]' : '';

        self::write(sprintf(
            '[TIMER%s] %-40s  %.2f ms  |  Peak: %.2f MB',
            $suffix,
            $label,
            $elapsedMs,
            $peakMb
        ));

        return $elapsedMs;
    }

    // ------------------------------------------------------------------ //
    //  Database query profiling helper
    // ------------------------------------------------------------------ //

    /**
     * Profile a callable that executes a DB query.
     *
     * Usage:
     *   $result = ProfileTracker::profileQuery($mysqli, 'SELECT ...', function() use ($stmt) {
     *       $stmt->execute();
     *       return $stmt->get_result();
     *   });
     *
     * @param mixed    $db       mysqli instance (for reference logging only)
     * @param string   $sqlSnip  Short description or SQL snippet (first 120 chars logged)
     * @param callable $fn       The closure that actually runs the query.
     * @return mixed             Whatever the callable returns.
     */
    public static function profileQuery($db, string $sqlSnip, callable $fn) {
        $t0     = microtime(true);
        $result = $fn();
        $ms     = (microtime(true) - $t0) * 1000.0;

        if ($ms >= self::$slowQueryMs) {
            $safe = substr(preg_replace('/\s+/', ' ', $sqlSnip), 0, 120);
            self::write(sprintf(
                '[SLOW-QUERY] %.2f ms  |  SQL: %s',
                $ms,
                $safe
            ));
        }

        return $result;
    }

    // ------------------------------------------------------------------ //
    //  Memory snapshot
    // ------------------------------------------------------------------ //

    /**
     * Emit an instant memory snapshot to the log.
     *
     * @param string $context  Label to identify the snapshot location.
     */
    public static function memorySnapshot(string $context = 'checkpoint'): void {
        $peakMb    = round(memory_get_peak_usage(true)    / 1048576, 2);
        $currentMb = round(memory_get_usage(true)         / 1048576, 2);

        self::write(sprintf(
            '[MEMORY] %-30s  Current: %.2f MB  |  Peak: %.2f MB',
            $context,
            $currentMb,
            $peakMb
        ));
    }

    // ------------------------------------------------------------------ //
    //  Script-level summary
    // ------------------------------------------------------------------ //

    /**
     * Emit a final execution summary — call once at the very end of a
     * CLI daemon cycle or a long-running HTTP request.
     *
     * @param string $scriptName  Descriptive name for the process.
     */
    public static function summary(string $scriptName = 'script'): void {
        $wallMs  = (microtime(true) - ($_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true))) * 1000.0;
        $peakMb  = round(memory_get_peak_usage(true) / 1048576, 2);

        self::write(sprintf(
            '[SUMMARY] %-30s  Wall: %.2f ms  |  Peak: %.2f MB',
            $scriptName,
            $wallMs,
            $peakMb
        ));
    }

    // ------------------------------------------------------------------ //
    //  Set threshold
    // ------------------------------------------------------------------ //

    /**
     * Override the slow-query threshold (default 200 ms).
     *
     * @param int $ms  New threshold in milliseconds.
     */
    public static function setSlowQueryThreshold(int $ms): void {
        self::$slowQueryMs = max(1, $ms);
    }

    // ------------------------------------------------------------------ //
    //  Internal writer
    // ------------------------------------------------------------------ //

    private static function write(string $line): void {
        $entry = sprintf("[%s] %s\n", date('Y-m-d H:i:s'), $line);
        @file_put_contents(self::logPath(), $entry, FILE_APPEND | LOCK_EX);
    }
}
