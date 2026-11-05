<?php

declare(strict_types=1);

namespace Waskita\Security\Reports;

use Illuminate\Support\Str;
use Waskita\Security\Core\AuditEngine;
use Waskita\Security\Core\AuditResult;

/**
 * Formats results specifically tailored for AI Agents
 * (Hermes, Claude, ChatGPT, GitHub Copilot, etc.)
 *
 * Produces structured JSON with clear action items, prioritised
 * fix instructions, and code-diff suggestions that agents can
 * apply directly.
 */
class AgentReportFormatter
{
    /**
     * Severity ordering for priority sorting (lower index = higher priority).
     */
    private const SEVERITY_ORDER = [
        'CRITICAL' => 0,
        'HIGH'     => 1,
        'MEDIUM'   => 2,
        'LOW'      => 3,
        'INFO'     => 4,
    ];

    /**
     * Well-known CVEs mapped to common vulnerability rule IDs.
     *
     * @var array<string, list<string>>
     */
    private const KNOWN_CVES = [
        'ENV_DEBUG_ENABLED'            => ['CVE-2021-3129'],
        'ENV_APP_KEY_DEFAULT'          => ['CVE-2018-15133'],
        'SQL_RAW_INJECTION'            => ['CVE-2019-12248'],
        'XSS_UNESCAPED_OUTPUT'         => ['CVE-2020-5260'],
        'FILE_UPLOAD_UNRESTRICTED'     => ['CVE-2021-21263'],
        'UNSERIALIZE_RCE'             => ['CVE-2022-31279'],
        'debug_mode_production'        => ['CVE-2021-3129'],
        'app_key_exposed'              => ['CVE-2018-15133'],
    ];

    /**
     * Format audit engine results for AI-agent consumption.
     *
     * @param  AuditEngine  $engine     The engine after run() has been called.
     * @param  float        $durationMs Elapsed time in milliseconds.
     * @return string  JSON-encoded agent report.
     */
    public function format(AuditEngine $engine, float $durationMs = 0.0): string
    {
        $summary = $engine->getSummary();
        $results = $engine->getResults();

        // Enrich and sort findings by severity priority
        $enriched = $this->enrichFindings($results);
        usort($enriched, fn (array $a, array $b): int =>
            (self::SEVERITY_ORDER[$a['severity']] ?? 4) <=> (self::SEVERITY_ORDER[$b['severity']] ?? 4)
        );

        $report = [
            'schema'      => 'waskita-agent-report/v1',
            'run_id'      => (string) Str::uuid(),
            'timestamp'   => now()->toIso8601String(),
            'duration_ms' => round($durationMs, 2),

            'environment' => [
                'laravel_version' => app()->version(),
                'php_version'     => PHP_VERSION,
                'app_env'         => (string) app()->environment(),
            ],

            'summary' => [
                'total'    => $summary['total'],
                'critical' => $summary['critical'],
                'high'     => $summary['high'],
                'medium'   => $summary['medium'],
                'low'      => $summary['low'],
                'info'     => $summary['info'],
            ],

            'action_items' => $this->buildActionItems($enriched),
            'findings'     => $enriched,
        ];

        return (string) json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Enrich AuditResult objects with agent-friendly fields.
     *
     * @param  AuditResult[]  $results
     * @return array<int, array<string, mixed>>
     */
    private function enrichFindings(array $results): array
    {
        $enriched = [];
        foreach ($results as $index => $result) {
            $id = $result->ruleId ?: 'LSEC-' . str_pad((string) ($index + 1), 4, '0', STR_PAD_LEFT);

            $enriched[] = [
                'id'                    => $id,
                'severity'              => $result->severity,
                'file'                  => $result->file ?: null,
                'line'                  => $result->line ?: null,
                'code'                  => $result->codeSnippet ?: null,
                'vulnerability'         => $result->title,
                'description'           => $result->description,
                'cve'                   => $this->resolveCves($result),
                'fix_instructions'      => $this->buildFixInstructions($result),
                'code_diff_suggestion'  => $this->buildDiffSuggestion($result),
                'category'              => $result->category,
            ];
        }

        return $enriched;
    }

    /**
     * Resolve CVE identifiers for a finding.
     *
     * @return list<string>
     */
    private function resolveCves(AuditResult $result): array
    {
        // Explicit CVE in result data
        if ($result->cveRef !== '') {
            return [$result->cveRef];
        }

        // Map by known rule ID
        if (isset(self::KNOWN_CVES[$result->ruleId])) {
            return self::KNOWN_CVES[$result->ruleId];
        }

        return [];
    }

    /**
     * Generate clear fix instructions for an AI agent.
     */
    private function buildFixInstructions(AuditResult $result): string
    {
        if ($result->suggestion !== '') {
            return $result->suggestion;
        }

        $file = $result->file ?: 'the affected file';

        return match ($result->severity) {
            AuditResult::SEVERITY_CRITICAL => "URGENT: Immediately remediate the issue in {$file}. This is a critical security vulnerability that may allow remote code execution or full system compromise.",
            AuditResult::SEVERITY_HIGH     => "Review and fix the vulnerability in {$file}. This issue poses a significant security risk.",
            AuditResult::SEVERITY_MEDIUM   => "Address the security concern in {$file} during the next development cycle.",
            AuditResult::SEVERITY_LOW      => "Consider hardening {$file} to follow security best practices.",
            default                        => "Informational finding in {$file}. Review for awareness.",
        };
    }

    /**
     * Build a before/after code diff suggestion.
     *
     * @return array{before: string|null, after: string|null}
     */
    private function buildDiffSuggestion(AuditResult $result): array
    {
        return [
            'before' => $result->codeSnippet ?: null,
            'after'  => null, // Populated by scanners that provide fix diffs
        ];
    }

    /**
     * Build a prioritised list of action items for the agent.
     *
     * @param  array<int, array<string, mixed>>  $findings  Already sorted by severity.
     * @return list<string>
     */
    private function buildActionItems(array $findings): array
    {
        $items = [];
        foreach ($findings as $finding) {
            $severity = $finding['severity'];
            $vuln     = $finding['vulnerability'];
            $file     = $finding['file'] ?? 'unknown file';
            $line     = $finding['line'] ?? '?';

            $items[] = "[{$severity}] Fix \"{$vuln}\" in {$file}:{$line}";
        }

        return $items;
    }
}
