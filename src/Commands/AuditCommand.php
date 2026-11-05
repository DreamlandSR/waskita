<?php

declare(strict_types=1);

namespace Waskita\Security\Commands;

use Illuminate\Console\Command;
use Waskita\Security\Core\AuditEngine;
use Waskita\Security\Core\AuditResult;
use Waskita\Security\Reports\AgentReportFormatter;
use Waskita\Security\Reports\ConsoleReportFormatter;
use Waskita\Security\Reports\JsonReportFormatter;

/**
 * Run a comprehensive security audit on a Laravel application.
 *
 * Orchestrates AuditEngine, selects the appropriate report formatter,
 * optionally writes output to a file, and exits with code 1 when
 * findings at or above the --fail-on severity are detected.
 */
class AuditCommand extends Command
{
    /** @var string */
    protected $signature = 'waskita:audit
        {--severity= : Minimum severity to display (critical, high, medium, low, info)}
        {--format=table : Output format (table, json, agent)}
        {--output= : Save output to file}
        {--fail-on=high : Fail with exit code 1 if findings reach this severity}
        {--scanner= : Run only a specific scanner (name or class fragment)}';

    /** @var string */
    protected $description = 'Run comprehensive security audit on Laravel application';

    /**
     * Severity ordering (highest first).
     */
    private const SEVERITY_ORDER = [
        'critical' => 0,
        'high'     => 1,
        'medium'   => 2,
        'low'      => 3,
        'info'     => 4,
    ];

    public function handle(AuditEngine $engine): int
    {
        $format       = strtolower((string) $this->option('format'));
        $failOn       = strtolower((string) $this->option('fail-on'));
        $severity     = $this->option('severity')
            ? strtolower((string) $this->option('severity'))
            : (string) config('waskita.severity_threshold', 'low');
        $outputFile   = $this->option('output') ? (string) $this->option('output') : null;
        $scannerFilter = $this->option('scanner') ? [(string) $this->option('scanner')] : [];

        // ── Run the audit ────────────────────────────────────────
        $startTime = microtime(true);

        $basePath = (string) base_path();
        $engine->run($basePath, $scannerFilter);

        $durationMs = (microtime(true) - $startTime) * 1000;

        // ── Filter by severity threshold ─────────────────────────
        $filteredResults = $this->filterBySeverity($engine->getResults(), $severity);

        // ── Format & output ──────────────────────────────────────
        $reportContent = $this->renderReport($engine, $format, $failOn, $durationMs);

        // Save to file if requested
        if ($outputFile !== null && $reportContent !== null) {
            file_put_contents($outputFile, $reportContent);
            $this->info("Report saved to: {$outputFile}");
        }

        // ── Determine exit code ──────────────────────────────────
        $hasFailing = $this->hasFailingFindings($engine->getResults(), $failOn);

        if ($hasFailing) {
            $this->error("Audit FAILED: findings at or above \"{$failOn}\" severity detected.");
            return self::FAILURE;
        }

        $this->info('Audit PASSED.');
        return self::SUCCESS;
    }

    /**
     * Render the report using the chosen formatter.
     */
    private function renderReport(
        AuditEngine $engine,
        string $format,
        string $failOn,
        float $durationMs,
    ): ?string {
        return match ($format) {
            'json' => $this->renderJson($engine, $durationMs),
            'agent' => $this->renderAgent($engine, $durationMs),
            default => $this->renderTable($engine, $failOn, $durationMs),
        };
    }

    /**
     * Render JSON format and output to console.
     */
    private function renderJson(AuditEngine $engine, float $durationMs): string
    {
        $formatter = new JsonReportFormatter();
        $json = $formatter->format($engine, $durationMs);
        $this->line($json);

        return $json;
    }

    /**
     * Render agent-friendly JSON format.
     */
    private function renderAgent(AuditEngine $engine, float $durationMs): string
    {
        $formatter = new AgentReportFormatter();
        $json = $formatter->format($engine, $durationMs);
        $this->line($json);

        return $json;
    }

    /**
     * Render human-friendly console table format.
     */
    private function renderTable(AuditEngine $engine, string $failOn, float $durationMs): null
    {
        $formatter = new ConsoleReportFormatter();
        $formatter->render($this->output, $engine, $failOn, $durationMs);

        return null; // Console output is written directly, not captured
    }

    /**
     * Filter results to only include those at or above the given severity.
     *
     * @param  AuditResult[]  $results
     * @return AuditResult[]
     */
    private function filterBySeverity(array $results, string $minSeverity): array
    {
        $threshold = self::SEVERITY_ORDER[strtolower($minSeverity)] ?? 4;

        return array_filter(
            $results,
            fn (AuditResult $r): bool =>
                (self::SEVERITY_ORDER[strtolower($r->severity)] ?? 4) <= $threshold
        );
    }

    /**
     * Check whether any finding meets or exceeds the fail-on threshold.
     *
     * @param  AuditResult[]  $results
     */
    private function hasFailingFindings(array $results, string $failOn): bool
    {
        $threshold = self::SEVERITY_ORDER[strtolower($failOn)] ?? 1;

        foreach ($results as $result) {
            $level = self::SEVERITY_ORDER[strtolower($result->severity)] ?? 4;
            if ($level <= $threshold) {
                return true;
            }
        }

        return false;
    }
}
