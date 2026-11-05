<?php

declare(strict_types=1);

namespace Waskita\Security\Core;

/**
 * RuleValidator - Validasi struktur file YAML rule.
 *
 * Memastikan setiap rule memiliki key yang diperlukan:
 * id, name, severity, category, targets, checks.
 */
class RuleValidator
{
    /** @var string[] Key wajib yang harus ada di setiap rule */
    private const REQUIRED_KEYS = [
        'id',
        'name',
        'severity',
        'category',
    ];

    /** @var string[] Key opsional yang dikenali */
    private const OPTIONAL_KEYS = [
        'description',
        'targets',
        'checks',
        'suggestion',
        'cve_ref',
        'enabled',
        'tags',
    ];

    /** @var string[] Severity yang valid */
    private const VALID_SEVERITIES = [
        'CRITICAL',
        'HIGH',
        'MEDIUM',
        'LOW',
        'INFO',
    ];

    /** @var array<int, array{rule_id: string, field: string, message: string}> */
    private array $errors = [];

    /**
     * Validasi satu rule array.
     *
     * @param array<string, mixed> $rule Data rule dari YAML
     * @return bool true jika valid
     */
    public function validate(array $rule): bool
    {
        $this->errors = [];
        $ruleId = $rule['id'] ?? 'unknown';

        // Cek required keys
        foreach (self::REQUIRED_KEYS as $key) {
            if (! array_key_exists($key, $rule) || empty($rule[$key])) {
                $this->errors[] = [
                    'rule_id' => (string) $ruleId,
                    'field' => $key,
                    'message' => "Key wajib '{$key}' tidak ditemukan atau kosong.",
                ];
            }
        }

        // Validasi severity
        if (isset($rule['severity']) && ! in_array(strtoupper((string) $rule['severity']), self::VALID_SEVERITIES, true)) {
            $this->errors[] = [
                'rule_id' => (string) $ruleId,
                'field' => 'severity',
                'message' => "Severity '{$rule['severity']}' tidak valid. Gunakan: " . implode(', ', self::VALID_SEVERITIES),
            ];
        }

        // Validasi targets (jika ada, harus array)
        if (isset($rule['targets']) && ! is_array($rule['targets'])) {
            $this->errors[] = [
                'rule_id' => (string) $ruleId,
                'field' => 'targets',
                'message' => "'targets' harus berupa array.",
            ];
        }

        // Validasi checks (jika ada, harus array)
        if (isset($rule['checks']) && ! is_array($rule['checks'])) {
            $this->errors[] = [
                'rule_id' => (string) $ruleId,
                'field' => 'checks',
                'message' => "'checks' harus berupa array.",
            ];
        }

        return count($this->errors) === 0;
    }

    /**
     * Validasi kumpulan rules.
     *
     * @param array<string, array<string, mixed>> $rules
     * @return bool true jika semua valid
     */
    public function validateAll(array $rules): bool
    {
        $allValid = true;

        foreach ($rules as $rule) {
            if (! $this->validate($rule)) {
                $allValid = false;
            }
        }

        return $allValid;
    }

    /**
     * Ambil daftar error dari validasi terakhir.
     *
     * @return array<int, array{rule_id: string, field: string, message: string}>
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    /**
     * Cek apakah ada error pada validasi terakhir.
     */
    public function hasErrors(): bool
    {
        return count($this->errors) > 0;
    }
}
