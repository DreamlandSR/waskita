<?php

declare(strict_types=1);

namespace Waskita\Security\Core;

/**
 * AuditResult - Representasi satu temuan keamanan (security finding).
 *
 * Menyimpan informasi lengkap tentang vulnerability yang ditemukan,
 * termasuk lokasi file, severity, saran perbaikan, dan referensi CVE.
 */
class AuditResult implements \JsonSerializable
{
    // Severity levels
    public const SEVERITY_CRITICAL = 'CRITICAL';
    public const SEVERITY_HIGH = 'HIGH';
    public const SEVERITY_MEDIUM = 'MEDIUM';
    public const SEVERITY_LOW = 'LOW';
    public const SEVERITY_INFO = 'INFO';

    // Severity penalties untuk scoring
    public const PENALTIES = [
        self::SEVERITY_CRITICAL => 25,
        self::SEVERITY_HIGH => 15,
        self::SEVERITY_MEDIUM => 5,
        self::SEVERITY_LOW => 2,
        self::SEVERITY_INFO => 0,
    ];

    public function __construct(
        public readonly string $ruleId,
        public readonly string $category,
        public readonly string $severity,
        public readonly string $title,
        public readonly string $description,
        public readonly string $file = '',
        public readonly int $line = 0,
        public readonly string $codeSnippet = '',
        public readonly string $suggestion = '',
        public readonly string $cveRef = '',
    ) {}

    /**
     * Konversi ke array untuk report/serialization.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'rule_id' => $this->ruleId,
            'category' => $this->category,
            'severity' => $this->severity,
            'title' => $this->title,
            'description' => $this->description,
            'file' => $this->file,
            'line' => $this->line,
            'code_snippet' => $this->codeSnippet,
            'suggestion' => $this->suggestion,
            'cve_ref' => $this->cveRef,
        ];
    }

    /**
     * JSON serialization (implements JsonSerializable).
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): mixed
    {
        return $this->toArray();
    }

    public function isCritical(): bool
    {
        return $this->severity === self::SEVERITY_CRITICAL;
    }

    public function isHigh(): bool
    {
        return $this->severity === self::SEVERITY_HIGH;
    }

    public function isMedium(): bool
    {
        return $this->severity === self::SEVERITY_MEDIUM;
    }

    public function isLow(): bool
    {
        return $this->severity === self::SEVERITY_LOW;
    }

    public function isInfo(): bool
    {
        return $this->severity === self::SEVERITY_INFO;
    }

    /**
     * Hitung penalty score untuk temuan ini.
     */
    public function getPenalty(): int
    {
        return self::PENALTIES[$this->severity] ?? 0;
    }
}
