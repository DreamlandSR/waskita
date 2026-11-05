<?php

declare(strict_types=1);

namespace Waskita\Security\Core;

/**
 * ScannerInterface - Kontrak dasar untuk semua security scanner.
 *
 * Setiap scanner harus mengimplementasikan interface ini agar bisa
 * dijalankan oleh AuditEngine secara otomatis.
 */
interface ScannerInterface
{
    /**
     * Nama scanner (untuk identifikasi di report).
     */
    public function getName(): string;

    /**
     * Deskripsi singkat tentang apa yang dicek oleh scanner ini.
     */
    public function getDescription(): string;

    /**
     * Jalankan scan terhadap project Laravel di basePath.
     *
     * @param string $basePath Root directory project Laravel
     * @param array<string, mixed> $config Konfigurasi tambahan dari waskita.php
     * @return AuditResult[] Daftar temuan keamanan
     */
    public function scan(string $basePath, array $config = []): array;
}
