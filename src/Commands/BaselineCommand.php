<?php

declare(strict_types=1);

namespace Waskita\Security\Commands;

use Illuminate\Console\Command;
use Waskita\Security\Core\AuditEngine;
use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\BaselineManager;

/**
 * BaselineCommand - Membuat atau memperbarui file baseline keamanan Waskita.
 *
 * Perintah ini menjalankan pemindaian penuh terhadap project, mencatat semua
 * celah keamanan yang ada saat ini ke dalam 'waskita-baseline.json'.
 *
 * Pada audit berikutnya (CI/CD atau waskita:audit), semua temuan yang tercatat
 * di baseline ini akan disembunyikan sehingga hanya celah baru yang memicu failure.
 */
class BaselineCommand extends Command
{
    /** @var string */
    protected $signature = 'waskita:baseline
        {--path= : Path file baseline (default: waskita-baseline.json di root project)}
        {--scanner= : Jalankan hanya scanner tertentu}
        {--force : Timpa file baseline jika sudah ada}';

    /** @var string */
    protected $description = 'Generate baseline file (waskita-baseline.json) to record existing security findings';

    public function handle(AuditEngine $engine): int
    {
        $basePath = \function_exists('base_path') ? (string) \base_path() : (string) getcwd();
        $baselineManager = new BaselineManager();

        $defaultPath = $basePath . '/' . BaselineManager::DEFAULT_FILENAME;
        $baselineFile = $this->option('path') ? (string) $this->option('path') : $defaultPath;

        // Pastikan path absolut
        if (! str_starts_with($baselineFile, '/') && ! preg_match('/^[A-Z]:[\\\\\/]/i', $baselineFile)) {
            $baselineFile = $basePath . '/' . ltrim($baselineFile, '/');
        }

        $isExisting = file_exists($baselineFile);
        if ($isExisting && ! $this->option('force')) {
            $this->warn("File baseline sudah ada di: {$baselineFile}");
            if (! $this->confirm('Apakah Anda ingin menimpa file baseline tersebut?', true)) {
                $this->info('Pembuatan baseline dibatalkan.');
                return self::SUCCESS;
            }
        }

        $scannerFilter = $this->option('scanner') ? [(string) $this->option('scanner')] : [];

        $this->info('Menjalankan audit keamanan untuk menyusun baseline...');
        $startTime = microtime(true);

        $engine->run($basePath, $scannerFilter);
        $results = $engine->getResults();

        $count = $baselineManager->saveBaseline($results, $baselineFile);
        $durationMs = round((microtime(true) - $startTime) * 1000, 2);

        // Tampilkan ringkasan severity
        $severityCounts = [
            AuditResult::SEVERITY_CRITICAL => 0,
            AuditResult::SEVERITY_HIGH => 0,
            AuditResult::SEVERITY_MEDIUM => 0,
            AuditResult::SEVERITY_LOW => 0,
            AuditResult::SEVERITY_INFO => 0,
        ];

        foreach ($results as $res) {
            $sev = strtoupper($res->severity);
            if (isset($severityCounts[$sev])) {
                $severityCounts[$sev]++;
            }
        }

        $this->newLine();
        $this->line('╔══════════════════════════════════════════════════════════════╗');
        $this->line('║           Waskita Security Baseline Generated                ║');
        $this->line('╚══════════════════════════════════════════════════════════════╝');
        $this->newLine();

        $this->table(
            ['Severity', 'Recorded in Baseline'],
            [
                ['CRITICAL', $severityCounts[AuditResult::SEVERITY_CRITICAL]],
                ['HIGH',     $severityCounts[AuditResult::SEVERITY_HIGH]],
                ['MEDIUM',   $severityCounts[AuditResult::SEVERITY_MEDIUM]],
                ['LOW',      $severityCounts[AuditResult::SEVERITY_LOW]],
                ['INFO',     $severityCounts[AuditResult::SEVERITY_INFO]],
                ['TOTAL',    $count],
            ]
        );

        $this->newLine();
        $this->info("✓ Baseline berhasil disimpan ke: {$baselineFile}");
        $this->line("  Waktu pembuatan: {$durationMs} ms");
        $this->line("  Audit berikutnya dengan 'php artisan waskita:audit' otomatis mengecualikan {$count} temuan ini.");
        $this->newLine();

        return self::SUCCESS;
    }
}
