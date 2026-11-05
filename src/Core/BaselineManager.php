<?php

declare(strict_types=1);

namespace Waskita\Security\Core;

/**
 * BaselineManager - Mengelola baseline temuan keamanan (waskita-baseline.json).
 *
 * Konsep Baseline:
 * Saat mengadopsi Waskita pada project yang sudah berjalan (legacy), baseline
 * mencatat seluruh temuan celah keamanan yang saat ini sudah ada (existing findings).
 *
 * Pada audit-audit berikutnya di CI/CD, temuan yang terdaftar di baseline akan
 * disembunyikan (suppressed), sehingga build hanya akan gagal (fail) jika ada
 * celah keamanan BARU yang diperkenalkan setelah baseline dibuat.
 */
class BaselineManager
{
    /** @var string Nama file baseline default */
    public const DEFAULT_FILENAME = 'waskita-baseline.json';

    /**
     * Buat signature unik untuk suatu temuan audit.
     * Menggunakan ruleId, file yang dinormalisasi, dan snippet kode agar toleran
     * terhadap pergeseran nomor baris saat kode lain diubah.
     */
    public function generateSignature(AuditResult $result): string
    {
        $normalizedFile = str_replace('\\', '/', $result->file);
        $normalizedSnippet = trim(preg_replace('/\s+/', ' ', $result->codeSnippet) ?? '');

        if ($normalizedSnippet !== '') {
            $raw = $result->ruleId . '|' . $normalizedFile . '|' . $normalizedSnippet;
        } else {
            // Fallback jika tidak ada snippet (misal header keamanan HTTP)
            $raw = $result->ruleId . '|' . $normalizedFile . '|' . $result->line;
        }

        return sha1($raw);
    }

    /**
     * Simpan kumpulan temuan audit ke dalam file baseline JSON.
     *
     * @param AuditResult[] $results
     * @return int Jumlah temuan yang dicatat ke baseline
     */
    public function saveBaseline(array $results, string $filePath): int
    {
        $entries = [];

        foreach ($results as $result) {
            $entries[] = [
                'rule_id' => $result->ruleId,
                'category' => $result->category,
                'severity' => $result->severity,
                'title' => $result->title,
                'file' => str_replace('\\', '/', $result->file),
                'line' => $result->line,
                'code_snippet' => $result->codeSnippet,
                'signature' => $this->generateSignature($result),
            ];
        }

        $data = [
            'version' => 1,
            'generated_at' => date('c'),
            'generator' => 'Waskita Security Baseline (waskita:baseline)',
            'total_findings' => count($entries),
            'findings' => $entries,
        ];

        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new \RuntimeException('Gagal melakukan encode JSON untuk baseline.');
        }

        $dir = dirname($filePath);
        if (! is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        file_put_contents($filePath, $json . "\n");

        return count($entries);
    }

    /**
     * Muat data baseline dari file JSON.
     *
     * @return array<string, mixed>|null
     */
    public function loadBaseline(string $filePath): ?array
    {
        if (! file_exists($filePath)) {
            return null;
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            return null;
        }

        $data = json_decode($content, true);
        if (! is_array($data) || ! isset($data['findings']) || ! is_array($data['findings'])) {
            return null;
        }

        return $data;
    }

    /**
     * Filter temuan audit berdasarkan file baseline.
     *
     * @param AuditResult[] $results
     * @return array{active: AuditResult[], suppressed: AuditResult[], baseline_count: int}
     */
    public function filter(array $results, string $filePath): array
    {
        $baselineData = $this->loadBaseline($filePath);

        if ($baselineData === null) {
            return [
                'active' => $results,
                'suppressed' => [],
                'baseline_count' => 0,
            ];
        }

        // Kumpulkan daftar signature yang ada di baseline
        $signatures = [];
        foreach ($baselineData['findings'] as $item) {
            if (isset($item['signature']) && is_string($item['signature'])) {
                $signatures[$item['signature']] = true;
            }
        }

        $active = [];
        $suppressed = [];

        foreach ($results as $result) {
            $sig = $this->generateSignature($result);

            if (isset($signatures[$sig])) {
                $suppressed[] = $result;
            } else {
                $active[] = $result;
            }
        }

        return [
            'active' => $active,
            'suppressed' => $suppressed,
            'baseline_count' => count($signatures),
        ];
    }
}
