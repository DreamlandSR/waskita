<?php

declare(strict_types=1);

namespace Waskita\Security\Reports;

use Waskita\Security\Core\AuditEngine;
use Waskita\Security\Core\AuditResult;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Pretty terminal output formatter for human-readable security audit reports.
 *
 * Renders an ASCII banner, color-coded security score badge, findings table,
 * detailed vulnerability listing, and a final PASS/FAIL verdict.
 */
class ConsoleReportFormatter
{
    /** ANSI escape sequences */
    private const RESET     = "\033[0m";
    private const BOLD      = "\033[1m";
    private const RED       = "\033[31m";
    private const GREEN     = "\033[32m";
    private const YELLOW    = "\033[33m";
    private const CYAN      = "\033[36m";
    private const WHITE     = "\033[37m";
    private const BG_RED    = "\033[41m";
    private const BG_GREEN  = "\033[42m";
    private const BG_YELLOW = "\033[43m";

    /** Severity ordering (highest first). */
    private const SEVERITY_ORDER = [
        AuditResult::SEVERITY_CRITICAL,
        AuditResult::SEVERITY_HIGH,
        AuditResult::SEVERITY_MEDIUM,
        AuditResult::SEVERITY_LOW,
        AuditResult::SEVERITY_INFO,
    ];

    /** Severity label colors. */
    private const SEVERITY_COLORS = [
        'CRITICAL' => self::RED,
        'HIGH'     => self::RED,
        'MEDIUM'   => self::YELLOW,
        'LOW'      => self::CYAN,
        'INFO'     => self::WHITE,
    ];

    /**
     * Render the full audit report to the console.
     *
     * @param  OutputInterface  $output     Symfony console output.
     * @param  AuditEngine      $engine     The engine after run() has been called.
     * @param  string           $failOn     Severity threshold for PASS/FAIL verdict.
     * @param  float            $durationMs Elapsed time in milliseconds.
     * @return bool  True if the audit passed, false if it failed.
     */
    public function render(
        OutputInterface $output,
        AuditEngine $engine,
        string $failOn = 'high',
        float $durationMs = 0.0,
    ): bool {
        $summary   = $engine->getSummary();
        $results   = $engine->getResults();
        $bySev     = $engine->groupBySeverity();

        $this->renderBanner($output);
        $this->renderScoreBadge($output, $summary['score'], $summary['grade']);
        $this->renderSummaryTable($output, $summary);
        $this->renderFindings($output, $results);

        $passed = $this->renderVerdict($output, $bySev, strtoupper($failOn));

        $output->writeln('');
        $output->writeln(self::BOLD . '  Duration: ' . self::RESET . round($durationMs, 2) . ' ms');
        $output->writeln('');

        return $passed;
    }

    /**
     * Render the ASCII banner.
     */
    private function renderBanner(OutputInterface $output): void
    {
        $c = self::CYAN;
        $r = self::RESET;

        $output->writeln('');
        $output->writeln("{$c}  ╔══════════════════════════════════════════════════════════════╗{$r}");
        $output->writeln("{$c}  ║                                                              ║{$r}");
        $output->writeln("{$c}  ║   ██╗      █████╗ ██████╗  █████╗ ███████╗███████╗ ██████╗   ║{$r}");
        $output->writeln("{$c}  ║   ██║     ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝   ║{$r}");
        $output->writeln("{$c}  ║   ██║     ███████║██████╔╝███████║███████╗█████╗  ██║         ║{$r}");
        $output->writeln("{$c}  ║   ██║     ██╔══██║██╔══██╗██╔══██║╚════██║██╔══╝  ██║         ║{$r}");
        $output->writeln("{$c}  ║   ███████╗██║  ██║██║  ██║██║  ██║███████║███████╗╚██████╗   ║{$r}");
        $output->writeln("{$c}  ║   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝   ║{$r}");
        $output->writeln("{$c}  ║                                                              ║{$r}");
        $output->writeln("{$c}  ║            Security Vulnerability Audit — Agent              ║{$r}");
        $output->writeln("{$c}  ╚══════════════════════════════════════════════════════════════╝{$r}");
        $output->writeln('');
    }

    /**
     * Render a color-coded security score badge.
     */
    private function renderScoreBadge(OutputInterface $output, int $score, string $grade): void
    {
        $bg = match (true) {
            $score >= 90 => self::BG_GREEN,
            $score >= 70 => self::BG_YELLOW,
            default      => self::BG_RED,
        };

        $b = self::BOLD;
        $r = self::RESET;

        $output->writeln("  {$bg}{$b}  Security Score: {$score}/100  (Grade: {$grade})  {$r}");
        $output->writeln('');
    }

    /**
     * Render the summary table.
     *
     * @param  array<string, int|string>  $summary
     */
    private function renderSummaryTable(OutputInterface $output, array $summary): void
    {
        $b = self::BOLD;
        $r = self::RESET;

        $output->writeln("{$b}  ┌─────────────┬───────┐{$r}");
        $output->writeln("{$b}  │  Severity   │ Count │{$r}");
        $output->writeln("{$b}  ├─────────────┼───────┤{$r}");

        $map = [
            'CRITICAL' => $summary['critical'],
            'HIGH'     => $summary['high'],
            'MEDIUM'   => $summary['medium'],
            'LOW'      => $summary['low'],
            'INFO'     => $summary['info'],
        ];

        foreach ($map as $label => $count) {
            $color = self::SEVERITY_COLORS[$label] ?? self::WHITE;
            $pad   = str_pad(ucfirst(strtolower($label)), 11);
            $num   = str_pad((string) $count, 5);
            $output->writeln("  │ {$color}{$pad}{$r} │ {$num} │");
        }

        $total = str_pad((string) $summary['total'], 5);
        $output->writeln("{$b}  ├─────────────┼───────┤{$r}");
        $output->writeln("{$b}  │  Total      │ {$total} │{$r}");
        $output->writeln("{$b}  └─────────────┴───────┘{$r}");
        $output->writeln('');
    }

    /**
     * Render detailed finding cards.
     *
     * @param  AuditResult[]  $results
     */
    private function renderFindings(OutputInterface $output, array $results): void
    {
        if (empty($results)) {
            $output->writeln(self::GREEN . '  ✔ No security findings detected. Great job!' . self::RESET);
            $output->writeln('');
            return;
        }

        $b = self::BOLD;
        $r = self::RESET;
        $output->writeln("{$b}  ── Findings ──────────────────────────────────────────────{$r}");
        $output->writeln('');

        foreach ($results as $i => $result) {
            $color = self::SEVERITY_COLORS[$result->severity] ?? self::WHITE;
            $badge = "{$color}{$b} {$result->severity} {$r}";
            $num   = $i + 1;

            $output->writeln("  {$badge}  #{$num}: {$result->title}");
            $fileInfo = ($result->file ?: '—') . ($result->line ? ":{$result->line}" : '');
            $output->writeln("         File: {$fileInfo}");

            if ($result->codeSnippet !== '') {
                $output->writeln('         Code: ' . self::YELLOW . trim($result->codeSnippet) . self::RESET);
            }

            if ($result->suggestion !== '') {
                $output->writeln('          Fix: ' . self::GREEN . $result->suggestion . self::RESET);
            }

            $output->writeln('');
        }
    }

    /**
     * Render the PASS / FAIL verdict.
     *
     * @param  array<string, AuditResult[]>  $bySeverity  Grouped results from AuditEngine.
     * @param  string                         $failOn      Uppercase severity threshold.
     * @return bool  True if passed.
     */
    private function renderVerdict(OutputInterface $output, array $bySeverity, string $failOn): bool
    {
        $failed = $this->hasFailure($bySeverity, $failOn);
        $b = self::BOLD;
        $r = self::RESET;

        if ($failed) {
            $bg = self::BG_RED;
            $output->writeln(
                "{$bg}{$b}  ✖  VERDICT: FAIL — findings at or above \"{$failOn}\" severity detected  {$r}"
            );
        } else {
            $bg = self::BG_GREEN;
            $output->writeln(
                "{$bg}{$b}  ✔  VERDICT: PASS — no findings at or above \"{$failOn}\" severity  {$r}"
            );
        }

        return ! $failed;
    }

    /**
     * Check whether any finding meets or exceeds the fail-on threshold.
     *
     * @param  array<string, AuditResult[]>  $bySeverity
     */
    private function hasFailure(array $bySeverity, string $failOn): bool
    {
        $thresholdIndex = array_search($failOn, self::SEVERITY_ORDER, true);
        if ($thresholdIndex === false) {
            $thresholdIndex = 1; // default to HIGH
        }

        foreach (self::SEVERITY_ORDER as $index => $severity) {
            if ($index <= $thresholdIndex && ! empty($bySeverity[$severity] ?? [])) {
                return true;
            }
        }

        return false;
    }
}
