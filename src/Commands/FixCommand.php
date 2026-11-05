<?php

declare(strict_types=1);

namespace Waskita\Security\Commands;

use Illuminate\Console\Command;
use Waskita\Security\Core\AuditEngine;
use Waskita\Security\Core\AuditResult;

/**
 * Interactive security remediation helper.
 *
 * Runs the audit engine, locates findings (or a specific finding by ID),
 * displays before/after diffs and step-by-step guidance, and optionally
 * applies automated patches in non-dry-run mode.
 */
class FixCommand extends Command
{
    /** @var string */
    protected $signature = 'waskita:fix
        {--dry-run : Show suggested fixes without applying}
        {--finding= : Fix specific finding ID}';

    /** @var string */
    protected $description = 'Interactive security remediation helper';

    /** ANSI styling */
    private const GREEN  = "\033[32m";
    private const RED    = "\033[31m";
    private const YELLOW = "\033[33m";
    private const CYAN   = "\033[36m";
    private const BOLD   = "\033[1m";
    private const RESET  = "\033[0m";

    public function handle(AuditEngine $engine): int
    {
        $dryRun    = (bool) $this->option('dry-run');
        $findingId = $this->option('finding') ? (string) $this->option('finding') : null;

        $this->newLine();
        $this->line(self::BOLD . self::CYAN . '  Waskita — Security Remediation Helper' . self::RESET);
        if ($dryRun) {
            $this->line(self::YELLOW . '  [DRY RUN] Fixes will only be displayed, not applied.' . self::RESET);
        }
        $this->newLine();

        // ── Run audit to collect findings ────────────────────────
        $basePath = (string) base_path();
        $this->line('  Scanning project for fixable issues...');
        $engine->run($basePath);
        $findings = $engine->getResults();

        if (empty($findings)) {
            $this->line(self::GREEN . '  ✔ No security findings detected. Nothing to fix!' . self::RESET);
            $this->newLine();
            return self::SUCCESS;
        }

        // ── Filter by specific finding ID if requested ──────────
        if ($findingId !== null) {
            $findings = array_filter(
                $findings,
                fn (AuditResult $r): bool => strcasecmp($r->ruleId, $findingId) === 0
            );

            if (empty($findings)) {
                $this->error("  No finding found with ID \"{$findingId}\".");
                return self::FAILURE;
            }
        }

        // ── Process each finding ─────────────────────────────────
        $fixedCount = 0;
        $totalFixable = 0;

        foreach ($findings as $i => $finding) {
            $num = $i + 1;
            $this->displayFindingHeader($finding, $num);

            $hasAutomaticFix = $this->hasAutomaticFix($finding);
            if ($hasAutomaticFix) {
                $totalFixable++;
            }

            $this->displayRemediationGuide($finding);

            if ($dryRun) {
                $this->line(self::CYAN . '  [DRY RUN] Skipped application.' . self::RESET);
                $this->newLine();
                continue;
            }

            if ($hasAutomaticFix) {
                if ($this->confirm("  Apply automated fix for #{$num} ({$finding->ruleId})?", true)) {
                    $applied = $this->applyFix($finding, $basePath);
                    if ($applied) {
                        $this->line(self::GREEN . '  ✔ Fix applied successfully.' . self::RESET);
                        $fixedCount++;
                    } else {
                        $this->line(self::RED . '  ✖ Failed to apply automated fix. Manual action required.' . self::RESET);
                    }
                }
            } else {
                $this->line(self::YELLOW . '  ℹ This issue requires manual code modification.' . self::RESET);
            }

            $this->newLine();
        }

        // ── Summary ─────────────────────────────────────────────
        $this->line(self::BOLD . '  ── Remediation Summary ───────────────────────────────────' . self::RESET);
        $this->line("  Total findings reviewed: " . count($findings));
        if (! $dryRun) {
            $this->line("  Fixes applied: " . self::GREEN . (string) $fixedCount . self::RESET . " of {$totalFixable} fixable");
        }
        $this->newLine();

        return self::SUCCESS;
    }

    /**
     * Display finding header card.
     */
    private function displayFindingHeader(AuditResult $finding, int $index): void
    {
        $b = self::BOLD;
        $r = self::RESET;
        $y = self::YELLOW;

        $this->line("{$b}  #{$index} [{$finding->severity}] {$finding->title}{$r}");
        $this->line("     Rule ID:  {$finding->ruleId}");
        $fileInfo = ($finding->file ?: '—') . ($finding->line ? ":{$finding->line}" : '');
        $this->line("     Location: {$fileInfo}");

        if ($finding->cveRef !== '') {
            $this->line("     CVE Ref:  " . self::RED . $finding->cveRef . $r);
        }

        if ($finding->codeSnippet !== '') {
            $this->line("     Current:  {$y}" . trim($finding->codeSnippet) . "{$r}");
        }
    }

    /**
     * Display remediation instructions and code suggestions.
     */
    private function displayRemediationGuide(AuditResult $finding): void
    {
        $b = self::BOLD;
        $g = self::GREEN;
        $r = self::RESET;

        $this->newLine();
        $this->line("{$b}     Recommendation:{$r}");
        if ($finding->suggestion !== '') {
            $this->line("     {$g}{$finding->suggestion}{$r}");
        } else {
            $this->line("     Review {$finding->file} and apply defensive coding standards.");
        }

        // Show diff suggestion if available
        $diff = $this->getSuggestedDiff($finding);
        if ($diff !== null) {
            $this->newLine();
            $this->line("{$b}     Suggested Code Change:{$r}");
            $this->line(self::RED   . "     - " . $diff['before'] . $r);
            $this->line(self::GREEN . "     + " . $diff['after'] . $r);
        }
    }

    /**
     * Check whether an automated patch can be applied for this finding.
     */
    private function hasAutomaticFix(AuditResult $finding): bool
    {
        return match ($finding->ruleId) {
            'ENV_DEBUG_ENABLED',
            'ENV_APP_KEY_DEFAULT',
            'MISSING_SECURITY_HEADERS' => true,
            default => false,
        };
    }

    /**
     * Attempt automated fix for well-known configuration issues.
     */
    private function applyFix(AuditResult $finding, string $basePath): bool
    {
        return match ($finding->ruleId) {
            'ENV_DEBUG_ENABLED' => $this->fixEnvDebug($basePath),
            default             => false,
        };
    }

    /**
     * Fix APP_DEBUG=true in .env by setting it to false.
     */
    private function fixEnvDebug(string $basePath): bool
    {
        $envPath = rtrim($basePath, '/') . '/.env';
        if (! file_exists($envPath) || ! is_writable($envPath)) {
            return false;
        }

        $content = (string) file_get_contents($envPath);
        $updated = preg_replace('/^APP_DEBUG\s*=\s*true/mi', 'APP_DEBUG=false', $content);

        if ($updated === null || $updated === $content) {
            return false;
        }

        return file_put_contents($envPath, $updated) !== false;
    }

    /**
     * Get suggested before/after diff for a finding.
     *
     * @return array{before: string, after: string}|null
     */
    private function getSuggestedDiff(AuditResult $finding): ?array
    {
        return match ($finding->ruleId) {
            'ENV_DEBUG_ENABLED' => [
                'before' => 'APP_DEBUG=true',
                'after'  => 'APP_DEBUG=false',
            ],
            'SQL_RAW_INJECTION' => [
                'before' => 'DB::raw("SELECT * FROM users WHERE id = " . $id)',
                'after'  => 'DB::select("SELECT * FROM users WHERE id = ?", [$id])',
            ],
            'XSS_UNESCAPED_OUTPUT' => [
                'before' => '{!! $userInput !!}',
                'after'  => '{{ $userInput }}',
            ],
            default => null,
        };
    }
}
