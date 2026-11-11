<?php

declare(strict_types=1);

namespace Waskita\Security\Core;

use Waskita\Security\Scanners\CsrfScanner;
use Waskita\Security\Scanners\EnvironmentConfigScanner;
use Waskita\Security\Scanners\IdorScanner;
use Waskita\Security\Scanners\MassAssignmentScanner;
use Waskita\Security\Scanners\RateLimitScanner;
use Waskita\Security\Scanners\SecurityHeaderScanner;
use Waskita\Security\Scanners\SqlInjectionScanner;
use Waskita\Security\Scanners\XssScanner;

/**
 * AuditEngine - Orkestrator utama untuk seluruh security scanner.
 *
 * Menjalankan semua scanner terdaftar, mengumpulkan temuan,
 * menghitung Security Score (100 - penalties), dan mengelompokkan
 * hasil berdasarkan severity dan category.
 */
class AuditEngine
{
    /** @var ScannerInterface[] Daftar scanner aktif */
    private array $scanners = [];

    /** @var AuditResult[] Hasil audit yang terkumpul */
    private array $results = [];

    /** @var array<string, mixed> Konfigurasi waskita */
    private array $config;

    /**
     * @param array<string, mixed> $config
     * @param ScannerInterface[]|null $customScanners Jika null, muat 8 default scanner
     */
    public function __construct(array $config = [], ?array $customScanners = null)
    {
        $this->config = $config;

        if ($customScanners !== null) {
            $this->scanners = $customScanners;
        } else {
            $this->registerDefaultScanners();
        }
    }

    /**
     * Registrasi 8 scanner bawaan Waskita.
     */
    private function registerDefaultScanners(): void
    {
        $this->scanners = [
            new MassAssignmentScanner(),
            new IdorScanner(),
            new XssScanner(),
            new SqlInjectionScanner(),
            new CsrfScanner(),
            new SecurityHeaderScanner(),
            new EnvironmentConfigScanner(),
            new RateLimitScanner(),
        ];
    }

    /**
     * Tambah custom scanner ke engine.
     */
    public function addScanner(ScannerInterface $scanner): self
    {
        $this->scanners[] = $scanner;

        return $this;
    }

    /**
     * Ambil daftar scanner terdaftar.
     *
     * @return ScannerInterface[]
     */
    public function getScanners(): array
    {
        return $this->scanners;
    }

    /**
     * Jalankan audit pada project directory.
     *
     * @param string $basePath Root directory aplikasi Laravel
     * @param string[] $onlyScanners Jika ditentukan, hanya scanner ini yang dijalankan (by class name or scanner name)
     * @return AuditResult[] Semua temuan keamanan
     */
    public function run(string $basePath, array $onlyScanners = []): array
    {
        $this->results = [];
        $normalizedBasePath = rtrim($basePath, '/');

        foreach ($this->scanners as $scanner) {
            // Filter jika ada scanner whitelist
            if (! empty($onlyScanners)) {
                $matched = false;
                foreach ($onlyScanners as $filter) {
                    if (str_contains(strtolower($scanner->getName()), strtolower($filter))
                        || str_contains(strtolower(get_class($scanner)), strtolower($filter))) {
                        $matched = true;
                        break;
                    }
                }

                if (! $matched) {
                    continue;
                }
            }

            try {
                $scannerResults = $scanner->scan($normalizedBasePath, $this->config);
                $this->results = array_merge($this->results, $scannerResults);
            } catch (\Throwable $e) {
                // Catat jika ada scanner gagal tapi jangan hentikan scanner lain
                $this->results[] = new AuditResult(
                    ruleId: 'SCANNER_INTERNAL_ERROR',
                    category: 'internal',
                    severity: AuditResult::SEVERITY_INFO,
                    title: "Scanner error: {$scanner->getName()}",
                    description: "Terjadi error saat menjalankan scanner: {$e->getMessage()}",
                    suggestion: "Periksa konfigurasi scanner dan pastikan file project dapat dibaca.",
                );
            }
        }

        // Filter temuan yang ditandai dengan anotasi inline @waskita-ignore
        $this->results = $this->filterIgnoredFindings($this->results, $normalizedBasePath);

        return $this->results;
    }

    /**
     * Filter temuan yang memiliki anotasi @waskita-ignore pada baris kode atau baris sebelumnya.
     *
     * Format yang didukung:
     * - // @waskita-ignore
     * - // @waskita-ignore RULE_ID
     * - // @waskita-ignore RULE_1, RULE_2: alasan
     * - {{-- @waskita-ignore --}} (Blade)
     * - /* @waskita-ignore * /
     *
     * @param AuditResult[] $results
     * @return AuditResult[]
     */
    private function filterIgnoredFindings(array $results, string $basePath): array
    {
        $filtered = [];
        $fileLinesCache = [];

        foreach ($results as $result) {
            if (! $result->file || ! $result->line) {
                $filtered[] = $result;
                continue;
            }

            $fullPath = $basePath . '/' . ltrim($result->file, '/');
            if (! file_exists($fullPath)) {
                $filtered[] = $result;
                continue;
            }

            if (! isset($fileLinesCache[$fullPath])) {
                $fileLinesCache[$fullPath] = file($fullPath, FILE_IGNORE_NEW_LINES) ?: [];
            }

            $lines = $fileLinesCache[$fullPath];
            $targetLine = $result->line; // 1-based

            $isIgnored = false;
            // Periksa baris saat ini, 1 baris sebelumnya, dan 2 baris sebelumnya
            $indicesToCheck = [
                $targetLine - 1, // baris kode itu sendiri (0-indexed)
                $targetLine - 2, // 1 baris sebelumnya
                $targetLine - 3, // 2 baris sebelumnya
            ];

            foreach ($indicesToCheck as $idx) {
                if ($idx < 0 || ! isset($lines[$idx])) {
                    continue;
                }

                $lineContent = $lines[$idx];

                if (preg_match('/@waskita-ignore\b\s*([^:\n\r*]*)(?::\s*([^\n\r*]+))?/i', $lineContent, $matches)) {
                    $ruleParams = isset($matches[1]) ? trim($matches[1], " \t\n\r\0\x0B*-{}") : '';

                    if ($ruleParams === '' || $ruleParams === '*/') {
                        // Blanket ignore untuk baris ini
                        $isIgnored = true;
                        break;
                    }

                    // Cocokkan ruleId, category, atau kata kunci
                    $tokens = preg_split('/[\s,]+/', $ruleParams);
                    foreach ($tokens as $token) {
                        $token = trim($token, " \t\n\r\0\x0B*-{}");
                        if ($token === '') {
                            continue;
                        }

                        if (
                            str_contains(strtoupper($result->ruleId), strtoupper($token))
                            || str_contains(strtoupper($result->category), strtoupper($token))
                            || str_contains(strtoupper($result->title), strtoupper($token))
                        ) {
                            $isIgnored = true;
                            break 2;
                        }
                    }
                }
            }

            if (! $isIgnored) {
                $filtered[] = $result;
            }
        }

        return $filtered;
    }

    /**
     * Hitung Security Score dari 0 hingga 100.
     *
     * Penalti:
     * - CRITICAL: -25
     * - HIGH:     -15
     * - MEDIUM:   -5
     * - LOW:      -2
     * - INFO:      0
     */
    public function calculateScore(): int
    {
        $score = 100;

        foreach ($this->results as $result) {
            $score -= $result->getPenalty();
        }

        return max(0, $score);
    }

    /**
     * Hitung huruf peringkat keamanan (A, B, C, D, F) berdasarkan score.
     */
    public function getGrade(): string
    {
        $score = $this->calculateScore();

        return match (true) {
            $score >= 90 => 'A',
            $score >= 80 => 'B',
            $score >= 70 => 'C',
            $score >= 60 => 'D',
            default => 'F',
        };
    }

    /**
     * Kelompokkan hasil berdasarkan severity.
     *
     * @return array<string, AuditResult[]>
     */
    public function groupBySeverity(): array
    {
        $grouped = [
            AuditResult::SEVERITY_CRITICAL => [],
            AuditResult::SEVERITY_HIGH => [],
            AuditResult::SEVERITY_MEDIUM => [],
            AuditResult::SEVERITY_LOW => [],
            AuditResult::SEVERITY_INFO => [],
        ];

        foreach ($this->results as $result) {
            $severity = strtoupper($result->severity);
            if (isset($grouped[$severity])) {
                $grouped[$severity][] = $result;
            } else {
                $grouped[$severity] = [$result];
            }
        }

        return $grouped;
    }

    /**
     * Kelompokkan hasil berdasarkan category.
     *
     * @return array<string, AuditResult[]>
     */
    public function groupByCategory(): array
    {
        $grouped = [];

        foreach ($this->results as $result) {
            $cat = $result->category ?: 'general';
            $grouped[$cat][] = $result;
        }

        return $grouped;
    }

    /**
     * Ringkasan statistik jumlah temuan per severity.
     *
     * @return array{
     *   total: int,
     *   critical: int,
     *   high: int,
     *   medium: int,
     *   low: int,
     *   info: int,
     *   score: int,
     *   grade: string
     * }
     */
    public function getSummary(): array
    {
        $bySeverity = $this->groupBySeverity();

        return [
            'total' => count($this->results),
            'critical' => count($bySeverity[AuditResult::SEVERITY_CRITICAL] ?? []),
            'high' => count($bySeverity[AuditResult::SEVERITY_HIGH] ?? []),
            'medium' => count($bySeverity[AuditResult::SEVERITY_MEDIUM] ?? []),
            'low' => count($bySeverity[AuditResult::SEVERITY_LOW] ?? []),
            'info' => count($bySeverity[AuditResult::SEVERITY_INFO] ?? []),
            'score' => $this->calculateScore(),
            'grade' => $this->getGrade(),
        ];
    }

    /**
     * Ambil semua hasil audit terakhir.
     *
     * @return AuditResult[]
     */
    public function getResults(): array
    {
        return $this->results;
    }

    /**
     * Atur ulang hasil audit (misalnya setelah difilter oleh baseline).
     *
     * @param AuditResult[] $results
     */
    public function setResults(array $results): self
    {
        $this->results = $results;

        return $this;
    }
}
