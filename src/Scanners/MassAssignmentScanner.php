<?php

declare(strict_types=1);

namespace Waskita\Security\Scanners;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\ScannerInterface;

/**
 * MassAssignmentScanner - Memindai kerentanan Mass Assignment pada Eloquent Models dan Controllers.
 *
 * Pemeriksaan:
 * 1. $guarded = [] (empty guarded array) -> CRITICAL (Privilege Escalation, CVE-2018-15133 pattern)
 * 2. $fillable berisi kolom sensitif: role, is_admin, admin, password, permissions, dll -> HIGH
 * 3. Controller memanggil Model::create($request->all()) atau $request->except(...) -> HIGH
 */
class MassAssignmentScanner implements ScannerInterface
{
    /** @var string[] Kolom sensitif yang tidak boleh ada di $fillable */
    private const SENSITIVE_COLUMNS = [
        'role',
        'roles',
        'is_admin',
        'admin',
        'is_superadmin',
        'superadmin',
        'password',
        'remember_token',
        'email_verified_at',
        'permissions',
        'permission',
        'balance',
        'credit',
        'wallet',
        'verified',
        'is_verified',
    ];

    public function getName(): string
    {
        return 'Mass Assignment Scanner';
    }

    public function getDescription(): string
    {
        return 'Mendeteksi celah Mass Assignment pada Model Eloquent ($guarded = [], $fillable sensitif) dan Controller ($request->all()).';
    }

    public function scan(string $basePath, array $config = []): array
    {
        $results = [];

        // 1. Scan Model Eloquent di app/Models dan app/
        $modelFiles = $this->findModelFiles($basePath);
        foreach ($modelFiles as $file) {
            $results = array_merge($results, $this->scanModelFile($file, $basePath));
        }

        // 2. Scan Controller di app/Http/Controllers
        $controllerFiles = $this->findPhpFiles($basePath . '/app/Http/Controllers');
        foreach ($controllerFiles as $file) {
            $results = array_merge($results, $this->scanControllerFile($file, $basePath));
        }

        return $results;
    }

    /**
     * Scan satu file Model Eloquent.
     *
     * @return AuditResult[]
     */
    private function scanModelFile(string $filePath, string $basePath): array
    {
        $results = [];
        $content = (string) file_get_contents($filePath);
        $relativePath = $this->getRelativePath($filePath, $basePath);
        $lines = explode("\n", $content);

        // Hanya audit file yang mendefinisikan class Eloquent Model
        if (! preg_match('/\bclass\s+\w+\s+extends\s+(Model|Authenticatable)\b/i', $content)) {
            // Bisa jadi class Model tanpa extends eksplisit atau abstract class
            if (! str_contains($content, 'Illuminate\Database\Eloquent\Model') &&
                ! str_contains($content, 'use HasFactory')) {
                return [];
            }
        }

        // Cek 1: $guarded = [] (CRITICAL)
        if (preg_match('/(protected|public)\s+\$guarded\s*=\s*\[\s*\]\s*;/m', $content, $matches, PREG_OFFSET_CAPTURE)) {
            $offset = $matches[0][1];
            $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;
            $snippet = trim($lines[$lineNumber - 1] ?? $matches[0][0]);

            $results[] = new AuditResult(
                ruleId: 'MASS_ASSIGN_EMPTY_GUARDED',
                category: 'mass_assignment',
                severity: AuditResult::SEVERITY_CRITICAL,
                title: 'Mass Assignment Protection Disabled ($guarded = [])',
                description: "Model mendefinisikan \$guarded = [], yang menonaktifkan proteksi mass assignment sepenuhnya. Penyerang dapat mengisi kolom sensitif seperti role, is_admin, atau password jika input request di-pass langsung.",
                file: $relativePath,
                line: $lineNumber,
                codeSnippet: $snippet,
                suggestion: "Gunakan \$fillable secara eksplisit dengan daftar kolom yang diizinkan untuk diisi pengguna, atau definisikan \$guarded dengan kolom sensitif.",
                cveRef: 'CVE-2018-15133 / CWE-915'
            );
        }

        // Cek 2: Kolom sensitif di dalam $fillable (HIGH)
        if (preg_match('/(protected|public)\s+\$fillable\s*=\s*\[([^\]]+)\]/s', $content, $matches, PREG_OFFSET_CAPTURE)) {
            $fillableBody = $matches[2][0];
            $startOffset = $matches[0][1];
            $matchStartLine = substr_count(substr($content, 0, $startOffset), "\n") + 1;

            foreach (self::SENSITIVE_COLUMNS as $sensitiveCol) {
                if (preg_match('/[\'"](' . preg_quote($sensitiveCol, '/') . ')[\'"]/i', $fillableBody, $colMatch, PREG_OFFSET_CAPTURE)) {
                    $colOffsetInFillable = $colMatch[0][1];
                    $totalOffset = $matches[2][1] + $colOffsetInFillable;
                    $lineNumber = substr_count(substr($content, 0, $totalOffset), "\n") + 1;
                    $snippet = trim($lines[$lineNumber - 1] ?? $colMatch[0][0]);

                    $foundCol = $colMatch[1][0];

                    $results[] = new AuditResult(
                        ruleId: 'MASS_ASSIGN_SENSITIVE_FILLABLE',
                        category: 'mass_assignment',
                        severity: AuditResult::SEVERITY_HIGH,
                        title: "Sensitive Column '{$foundCol}' in \$fillable",
                        description: "Kolom sensitif '{$foundCol}' terdaftar di dalam \$fillable. Jika input form/request diterima tanpa filter ketat, penyerang dapat mengubah hak akses atau kolom kritis ini (Privilege Escalation).",
                        file: $relativePath,
                        line: $lineNumber,
                        codeSnippet: $snippet,
                        suggestion: "Hapus '{$foundCol}' dari \$fillable. Ubah nilai kolom sensitif ini secara manual atau melalui method/controller khusus admin.",
                        cveRef: 'CWE-915'
                    );
                }
            }
        }

        return $results;
    }

    /**
     * Scan file Controller untuk penggunaan $request->all() / $request->except() di create/update.
     *
     * @return AuditResult[]
     */
    private function scanControllerFile(string $filePath, string $basePath): array
    {
        $results = [];
        $content = (string) file_get_contents($filePath);
        $relativePath = $this->getRelativePath($filePath, $basePath);
        $lines = explode("\n", $content);

        // Pola 1: Model::create($request->all()) atau Model::create(request()->all())
        // Pola 2: $model->update($request->all())
        // Pola 3: Model::create($request->except(...))
        $patterns = [
            '/(?:create|update|updateOrCreate|firstOrCreate)\s*\(\s*(?:\$request->all\(\)|request\(\)->all\(\))\s*\)/i' => [
                'rule' => 'MASS_ASSIGN_REQUEST_ALL',
                'severity' => AuditResult::SEVERITY_HIGH,
                'title' => 'Unsafe Mass Assignment: create/update($request->all())',
                'desc' => 'Penggunaan $request->all() langsung ke method Eloquent create/update berisiko mass assignment. Semua input dikirim langsung ke database tanpa validasi whitelist.',
                'suggestion' => 'Gunakan FormRequest dengan $request->validated(), atau batasi input dengan $request->only([...]).',
            ],
            '/(?:create|update|updateOrCreate|firstOrCreate)\s*\(\s*(?:\$request->except\(|request\(\)->except\()/i' => [
                'rule' => 'MASS_ASSIGN_REQUEST_EXCEPT',
                'severity' => AuditResult::SEVERITY_HIGH,
                'title' => 'Unsafe Mass Assignment: Blacklist Approach using $request->except()',
                'desc' => 'Penggunaan $request->except() menggunakan pendekatan blacklist yang rentan bypass jika ada parameter baru yang tidak terpikirkan.',
                'suggestion' => 'Gunakan pendekatan whitelist dengan $request->validated() atau $request->only([...]).',
            ],
        ];

        foreach ($patterns as $pattern => $meta) {
            if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $offset = $match[1];
                    $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;
                    $snippet = trim($lines[$lineNumber - 1] ?? $match[0]);

                    $results[] = new AuditResult(
                        ruleId: $meta['rule'],
                        category: 'mass_assignment',
                        severity: $meta['severity'],
                        title: $meta['title'],
                        description: $meta['desc'],
                        file: $relativePath,
                        line: $lineNumber,
                        codeSnippet: $snippet,
                        suggestion: $meta['suggestion'],
                        cveRef: 'CWE-915'
                    );
                }
            }
        }

        return $results;
    }

    /**
     * Cari semua file model Eloquent di project.
     *
     * @return string[]
     */
    private function findModelFiles(string $basePath): array
    {
        $modelsDir = $basePath . '/app/Models';
        if (is_dir($modelsDir)) {
            return $this->findPhpFiles($modelsDir);
        }

        // Fallback untuk Laravel lama di mana Model ada langsung di app/
        $appDir = $basePath . '/app';
        if (is_dir($appDir)) {
            $files = glob($appDir . '/*.php');
            return $files ?: [];
        }

        return [];
    }

    /**
     * Rekursif mencari file PHP dalam sebuah direktori.
     *
     * @return string[]
     */
    private function findPhpFiles(string $dir): array
    {
        if (! is_dir($dir)) {
            return [];
        }

        $files = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    private function getRelativePath(string $fullPath, string $basePath): string
    {
        $base = rtrim($basePath, '/') . '/';
        if (str_starts_with($fullPath, $base)) {
            return substr($fullPath, strlen($base));
        }

        return $fullPath;
    }
}
