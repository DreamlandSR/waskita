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

        return $this->results;
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
}
