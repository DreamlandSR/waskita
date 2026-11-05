<?php

declare(strict_types=1);

namespace Waskita\Security\Reports;

use Illuminate\Support\Str;
use Waskita\Security\Core\AuditEngine;
use Waskita\Security\Core\AuditResult;

/**
 * Formats AuditEngine results into clean, structured JSON.
 */
class JsonReportFormatter
{
    /**
     * Format audit engine results into structured JSON.
     *
     * @param  AuditEngine  $engine     The engine after run() has been called.
     * @param  float        $durationMs Elapsed time in milliseconds.
     * @return string  JSON-encoded report.
     */
    public function format(AuditEngine $engine, float $durationMs = 0.0): string
    {
        $summary = $engine->getSummary();
        $results = $engine->getResults();

        $report = [
            'run_id'         => (string) Str::uuid(),
            'timestamp'      => now()->toIso8601String(),
            'project_info'   => $this->projectInfo(),
            'security_score' => $summary['score'],
            'grade'          => $summary['grade'],
            'summary'        => [
                'critical_count' => $summary['critical'],
                'high_count'     => $summary['high'],
                'medium_count'   => $summary['medium'],
                'low_count'      => $summary['low'],
                'info_count'     => $summary['info'],
                'total_findings' => $summary['total'],
            ],
            'findings'    => $this->formatFindings($results),
            'duration_ms' => round($durationMs, 2),
        ];

        return (string) json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Gather project environment information.
     *
     * @return array<string, string>
     */
    private function projectInfo(): array
    {
        return [
            'laravel_version' => app()->version(),
            'php_version'     => PHP_VERSION,
            'environment'     => (string) app()->environment(),
        ];
    }

    /**
     * Normalise AuditResult objects into a consistent array structure.
     *
     * @param  AuditResult[]  $results
     * @return array<int, array<string, mixed>>
     */
    private function formatFindings(array $results): array
    {
        return array_values(array_map(
            fn (AuditResult $r): array => [
                'id'           => $r->ruleId,
                'category'     => $r->category,
                'severity'     => $r->severity,
                'title'        => $r->title,
                'description'  => $r->description,
                'file'         => $r->file ?: null,
                'line'         => $r->line ?: null,
                'code_snippet' => $r->codeSnippet ?: null,
                'suggestion'   => $r->suggestion ?: null,
                'cve_ref'      => $r->cveRef ?: null,
            ],
            $results,
        ));
    }
}
