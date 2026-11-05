<?php

declare(strict_types=1);

namespace Waskita\Security\Scanners;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\ScannerInterface;

/**
 * CsrfScanner - Mendeteksi kelemahan perlindungan CSRF pada aplikasi Laravel.
 *
 * Pemeriksaan:
 * 1. Wildcard '*' di CSRF except list (Laravel 11+: validateCsrfTokens(except: [...]), Laravel 10: VerifyCsrfToken $except)
 * 2. Route sensitif di dalam CSRF except list (login, register, password/*, checkout, payment)
 * 3. Form Blade <form method="POST"> yang tidak memiliki @csrf atau csrf_field()
 */
class CsrfScanner implements ScannerInterface
{
    /** @var string[] Pola route sensitif yang tidak boleh dikecualikan dari CSRF */
    private const SENSITIVE_ROUTES = [
        'login',
        'logout',
        'register',
        'password',
        'user',
        'profile',
        'checkout',
        'payment',
        'order',
        'transfer',
        'settings',
        'admin',
        'account',
    ];

    public function getName(): string
    {
        return 'CSRF Scanner';
    }

    public function getDescription(): string
    {
        return 'Mendeteksi kelemahan CSRF protection: wildcard except, route sensitif dikecualikan, dan form HTML tanpa @csrf directive.';
    }

    public function scan(string $basePath, array $config = []): array
    {
        $results = [];

        // 1. Cek konfigurasi CSRF exception
        $results = array_merge($results, $this->scanCsrfConfig($basePath));

        // 2. Cek form Blade tanpa @csrf
        $bladeFiles = $this->findBladeFiles($basePath . '/resources/views');
        foreach ($bladeFiles as $file) {
            $results = array_merge($results, $this->scanBladeForm($file, $basePath));
        }

        return $results;
    }

    /**
     * Scan konfigurasi CSRF exception pada bootstrap/app.php (Laravel 11+) dan VerifyCsrfToken (Laravel 10).
     *
     * @return AuditResult[]
     */
    private function scanCsrfConfig(string $basePath): array
    {
        $results = [];

        // Laravel 11+: bootstrap/app.php -> withMiddleware(function (Middleware $middleware) { ... ->validateCsrfTokens(except: [...]) })
        $bootstrapFile = $basePath . '/bootstrap/app.php';
        if (file_exists($bootstrapFile)) {
            $content = (string) file_get_contents($bootstrapFile);
            $lines = explode("\n", $content);

            // Cari validateCsrfTokens(except: [...])
            if (preg_match('/validateCsrfTokens\s*\(\s*except\s*:\s*\[([^\]]*)\]/s', $content, $match, PREG_OFFSET_CAPTURE)) {
                $exceptBody = $match[1][0];
                $offset = $match[0][1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;

                $results = array_merge($results, $this->analyzeExceptList($exceptBody, 'bootstrap/app.php', $lineNumber, $lines));
            }
        }

        // Laravel 10 dan sebelumnya: app/Http/Middleware/VerifyCsrfToken.php
        $csrfMiddleware = $basePath . '/app/Http/Middleware/VerifyCsrfToken.php';
        if (file_exists($csrfMiddleware)) {
            $content = (string) file_get_contents($csrfMiddleware);
            $lines = explode("\n", $content);

            // Cari protected $except = [...]
            if (preg_match('/(protected|public)\s+\$except\s*=\s*\[([^\]]*)\]/s', $content, $match, PREG_OFFSET_CAPTURE)) {
                $exceptBody = $match[2][0];
                $offset = $match[0][1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;

                $results = array_merge(
                    $results,
                    $this->analyzeExceptList($exceptBody, 'app/Http/Middleware/VerifyCsrfToken.php', $lineNumber, $lines)
                );
            }
        }

        return $results;
    }

    /**
     * Analisis except list untuk route sensitif dan wildcard.
     *
     * @return AuditResult[]
     */
    private function analyzeExceptList(string $exceptBody, string $relativePath, int $baseLine, array $lines): array
    {
        $results = [];

        // Cek wildcard '*'
        if (preg_match('/[\'"](\*)[\'"]/', $exceptBody)) {
            $snippet = trim($lines[$baseLine - 1] ?? $exceptBody);

            $results[] = new AuditResult(
                ruleId: 'CSRF_WILDCARD_EXCEPT',
                category: 'csrf',
                severity: AuditResult::SEVERITY_CRITICAL,
                title: "CSRF Protection Disabled Globally via Wildcard '*'",
                description: "CSRF verification dikecualikan untuk SEMUA route ('*'). Ini mematikan proteksi CSRF secara total, memungkinkan serangan cross-site request forgery di seluruh aplikasi.",
                file: $relativePath,
                line: $baseLine,
                codeSnippet: $snippet,
                suggestion: "Hapus '*' dari daftar pengecualian CSRF. Untuk API stateless, gunakan routes/api.php yang secara default tanpa CSRF.",
                cveRef: 'CWE-352'
            );
        }

        // Cek route sensitif
        if (preg_match_all('/[\'"]([^\'"]+)[\'"]/', $exceptBody, $routeMatches)) {
            foreach ($routeMatches[1] as $route) {
                if ($route === '*') {
                    continue; // Sudah ditangani di atas
                }

                foreach (self::SENSITIVE_ROUTES as $sensitive) {
                    if (str_contains(strtolower($route), $sensitive)) {
                        $snippet = trim($lines[$baseLine - 1] ?? $exceptBody);

                        $results[] = new AuditResult(
                            ruleId: 'CSRF_SENSITIVE_ROUTE_EXCLUDED',
                            category: 'csrf',
                            severity: AuditResult::SEVERITY_HIGH,
                            title: "Sensitive Route Excluded from CSRF: '{$route}'",
                            description: "Route sensitif '{$route}' dikecualikan dari proteksi CSRF. Penyerang dapat melakukan CSRF attack untuk aksi sensitif (login, payment, profile update).",
                            file: $relativePath,
                            line: $baseLine,
                            codeSnippet: $snippet,
                            suggestion: "Jangan kecualikan route sensitif dari CSRF. Jika ini webhook/API callback, gunakan HMAC signature verification.",
                            cveRef: 'CWE-352'
                        );
                        break; // Satu match per route cukup
                    }
                }
            }
        }

        return $results;
    }

    /**
     * Scan file Blade untuk <form method="POST"> tanpa @csrf.
     *
     * @return AuditResult[]
     */
    private function scanBladeForm(string $filePath, string $basePath): array
    {
        $results = [];
        $content = (string) file_get_contents($filePath);
        $relativePath = $this->getRelativePath($filePath, $basePath);
        $lines = explode("\n", $content);

        // Cari semua <form> tags dengan method POST, PUT, PATCH, DELETE
        $formPattern = '/<form\b[^>]*method\s*=\s*["\'](?:POST|PUT|PATCH|DELETE)["\'][^>]*>/si';

        if (preg_match_all($formPattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                $formTag = $match[0];
                $offset = $match[1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;

                // Cari isi form dari <form...> sampai </form>
                $formEndPos = stripos($content, '</form>', $offset);
                if ($formEndPos === false) {
                    $formEndPos = min($offset + 2000, strlen($content));
                }

                $formBody = substr($content, $offset, $formEndPos - $offset);

                // Cek apakah form memiliki @csrf, csrf_field(), atau input _token
                $hasCsrf = str_contains($formBody, '@csrf')
                    || str_contains($formBody, 'csrf_field()')
                    || str_contains($formBody, 'name="_token"')
                    || str_contains($formBody, "name='_token'");

                if (! $hasCsrf) {
                    $snippet = trim($lines[$lineNumber - 1] ?? $formTag);

                    $results[] = new AuditResult(
                        ruleId: 'CSRF_MISSING_TOKEN_IN_FORM',
                        category: 'csrf',
                        severity: AuditResult::SEVERITY_HIGH,
                        title: 'POST Form Missing @csrf Token Directive',
                        description: "Form HTML dengan method POST/PUT/PATCH/DELETE tidak memiliki @csrf directive. Request akan gagal (419 Page Expired) atau rentan CSRF jika proteksi dimatikan.",
                        file: $relativePath,
                        line: $lineNumber,
                        codeSnippet: $snippet,
                        suggestion: "Tambahkan directive @csrf tepat setelah tag <form>, contoh:\n<form method=\"POST\">\n    @csrf\n    ...\n</form>",
                        cveRef: 'CWE-352'
                    );
                }
            }
        }

        return $results;
    }

    /**
     * @return string[]
     */
    private function findBladeFiles(string $dir): array
    {
        if (! is_dir($dir)) {
            return [];
        }

        $files = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && str_ends_with($file->getFilename(), '.blade.php')) {
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
