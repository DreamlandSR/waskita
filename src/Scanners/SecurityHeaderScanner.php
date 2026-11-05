<?php

declare(strict_types=1);

namespace Waskita\Security\Scanners;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\ScannerInterface;

/**
 * SecurityHeaderScanner - Memeriksa keberadaan HTTP Security Headers di middleware atau konfigurasi.
 *
 * Headers yang diaudit:
 * - Strict-Transport-Security (HSTS): Melindungi dari MITM downgrade attack
 * - Content-Security-Policy (CSP): Mitigasi XSS dan data injection
 * - X-Frame-Options: Melindungi dari Clickjacking
 * - X-Content-Type-Options: Mencegah MIME type sniffing
 * - Referrer-Policy: Mengontrol informasi referrer yang bocor
 * - Permissions-Policy: Membatasi akses fitur browser (kamera, mikrofon, geolokasi)
 */
class SecurityHeaderScanner implements ScannerInterface
{
    /** @var array<string, array{severity: string, ruleId: string, title: string, description: string, suggestion: string}> */
    private const REQUIRED_HEADERS = [
        'Strict-Transport-Security' => [
            'severity' => AuditResult::SEVERITY_HIGH,
            'ruleId' => 'SEC_HEADER_HSTS_MISSING',
            'title' => 'Missing HTTP Strict-Transport-Security (HSTS) Header',
            'description' => 'Header HSTS tidak ditemukan. Tanpa HSTS, browser dapat mengakses situs via HTTP biasa, memungkinkan MITM downgrade attack dan SSL stripping.',
            'suggestion' => "Tambahkan header 'Strict-Transport-Security: max-age=31536000; includeSubDomains' di middleware atau server config.",
        ],
        'Content-Security-Policy' => [
            'severity' => AuditResult::SEVERITY_MEDIUM,
            'ruleId' => 'SEC_HEADER_CSP_MISSING',
            'title' => 'Missing Content-Security-Policy (CSP) Header',
            'description' => 'Header CSP tidak ditemukan. CSP membantu mencegah XSS dan data injection dengan membatasi sumber script/style yang diizinkan.',
            'suggestion' => "Tambahkan header 'Content-Security-Policy: default-src \\'self\\'; script-src \\'self\\'' atau gunakan package spatie/laravel-csp.",
        ],
        'X-Frame-Options' => [
            'severity' => AuditResult::SEVERITY_MEDIUM,
            'ruleId' => 'SEC_HEADER_X_FRAME_OPTIONS_MISSING',
            'title' => 'Missing X-Frame-Options Header',
            'description' => 'Header X-Frame-Options tidak ditemukan. Situs dapat di-embed dalam iframe oleh domain lain, memungkinkan Clickjacking attack.',
            'suggestion' => "Tambahkan header 'X-Frame-Options: DENY' atau 'SAMEORIGIN' di middleware.",
        ],
        'X-Content-Type-Options' => [
            'severity' => AuditResult::SEVERITY_MEDIUM,
            'ruleId' => 'SEC_HEADER_X_CONTENT_TYPE_OPTIONS_MISSING',
            'title' => 'Missing X-Content-Type-Options Header',
            'description' => 'Header X-Content-Type-Options tidak ditemukan. Browser dapat melakukan MIME type sniffing, memungkinkan file non-executable dieksekusi sebagai script.',
            'suggestion' => "Tambahkan header 'X-Content-Type-Options: nosniff' di middleware.",
        ],
        'Referrer-Policy' => [
            'severity' => AuditResult::SEVERITY_LOW,
            'ruleId' => 'SEC_HEADER_REFERRER_POLICY_MISSING',
            'title' => 'Missing Referrer-Policy Header',
            'description' => 'Header Referrer-Policy tidak ditemukan. URL lengkap (termasuk query string dengan data sensitif) bisa bocor ke situs pihak ketiga melalui Referer header.',
            'suggestion' => "Tambahkan header 'Referrer-Policy: strict-origin-when-cross-origin' atau 'no-referrer' di middleware.",
        ],
        'Permissions-Policy' => [
            'severity' => AuditResult::SEVERITY_LOW,
            'ruleId' => 'SEC_HEADER_PERMISSIONS_POLICY_MISSING',
            'title' => 'Missing Permissions-Policy Header',
            'description' => 'Header Permissions-Policy tidak ditemukan. Fitur browser (kamera, mikrofon, geolokasi) dapat diakses oleh embedded content tanpa kontrol.',
            'suggestion' => "Tambahkan header 'Permissions-Policy: camera=(), microphone=(), geolocation=()' di middleware untuk membatasi fitur browser.",
        ],
    ];

    public function getName(): string
    {
        return 'Security Headers Scanner';
    }

    public function getDescription(): string
    {
        return 'Memeriksa keberadaan HTTP Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) di middleware dan konfigurasi.';
    }

    public function scan(string $basePath, array $config = []): array
    {
        // Kumpulkan semua header yang ditemukan dari berbagai sumber
        $foundHeaders = [];

        // 1. Scan middleware files
        $middlewareDir = $basePath . '/app/Http/Middleware';
        if (is_dir($middlewareDir)) {
            foreach ($this->findPhpFiles($middlewareDir) as $file) {
                $this->extractHeadersFromPhp((string) file_get_contents($file), $foundHeaders);
            }
        }

        // 2. Scan bootstrap/app.php (Laravel 11+ middleware config)
        $bootstrapFile = $basePath . '/bootstrap/app.php';
        if (file_exists($bootstrapFile)) {
            $this->extractHeadersFromPhp((string) file_get_contents($bootstrapFile), $foundHeaders);
        }

        // 3. Scan app/Http/Kernel.php (Laravel 10 dan sebelumnya)
        $kernelFile = $basePath . '/app/Http/Kernel.php';
        if (file_exists($kernelFile)) {
            $kernelContent = (string) file_get_contents($kernelFile);
            $this->extractHeadersFromPhp($kernelContent, $foundHeaders);

            // Cek apakah ada security headers package terdaftar
            if (str_contains($kernelContent, 'SecurityHeaders')
                || str_contains($kernelContent, 'secure-headers')
                || str_contains($kernelContent, 'SecureHeaders')) {
                // Anggap semua header di-handle oleh package
                return [];
            }
        }

        // 4. Scan config files untuk package bepsvpt/secure-headers
        $secureHeadersConfig = $basePath . '/config/secure-headers.php';
        if (file_exists($secureHeadersConfig)) {
            $this->extractHeadersFromPhp((string) file_get_contents($secureHeadersConfig), $foundHeaders);
        }

        // 5. Scan .htaccess
        $htaccess = $basePath . '/public/.htaccess';
        if (file_exists($htaccess)) {
            $this->extractHeadersFromConfig((string) file_get_contents($htaccess), $foundHeaders);
        }

        // 6. Scan Nginx config hint (jika ada)
        $nginxConf = $basePath . '/nginx.conf';
        if (file_exists($nginxConf)) {
            $this->extractHeadersFromConfig((string) file_get_contents($nginxConf), $foundHeaders);
        }

        // 7. Scan composer.json untuk security header packages
        $composerFile = $basePath . '/composer.json';
        if (file_exists($composerFile)) {
            $composerContent = (string) file_get_contents($composerFile);
            if (str_contains($composerContent, 'spatie/laravel-csp')) {
                $foundHeaders['Content-Security-Policy'] = true;
            }
            if (str_contains($composerContent, 'bepsvpt/secure-headers')) {
                // Package ini menangani semua headers
                return [];
            }
        }

        // Jika tidak ada security header yang ditemukan sama sekali
        if (empty($foundHeaders)) {
            return [
                new AuditResult(
                    ruleId: 'SEC_HEADERS_MISSING_MIDDLEWARE',
                    category: 'security_headers',
                    severity: AuditResult::SEVERITY_HIGH,
                    title: 'Missing HTTP Security Headers Middleware',
                    description: 'Tidak ditemukan middleware atau konfigurasi yang mengatur HTTP Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy). Semua 6 header keamanan esensial tidak dikonfigurasi.',
                    suggestion: "Buat middleware SecurityHeaders atau install package 'bepsvpt/secure-headers' untuk mengamankan response HTTP secara komprehensif.",
                    cveRef: 'CWE-693'
                ),
            ];
        }

        // Laporkan header yang masih hilang
        $results = [];
        foreach (self::REQUIRED_HEADERS as $headerName => $meta) {
            if (! isset($foundHeaders[$headerName])) {
                $results[] = new AuditResult(
                    ruleId: $meta['ruleId'],
                    category: 'security_headers',
                    severity: $meta['severity'],
                    title: $meta['title'],
                    description: $meta['description'],
                    suggestion: $meta['suggestion'],
                    cveRef: 'CWE-693'
                );
            }
        }

        return $results;
    }

    /**
     * Ekstrak informasi header keamanan dari konten PHP (middleware, config, dll).
     *
     * @param array<string, bool> $foundHeaders
     */
    private function extractHeadersFromPhp(string $content, array &$foundHeaders): void
    {
        $contentLower = strtolower($content);

        foreach (array_keys(self::REQUIRED_HEADERS) as $header) {
            $headerLower = strtolower($header);

            // Cari dalam string PHP: 'Header-Name' atau "Header-Name"
            if (str_contains($contentLower, $headerLower)) {
                $foundHeaders[$header] = true;
            }
        }
    }

    /**
     * Ekstrak informasi header dari config server (.htaccess, nginx.conf).
     *
     * @param array<string, bool> $foundHeaders
     */
    private function extractHeadersFromConfig(string $content, array &$foundHeaders): void
    {
        $contentLower = strtolower($content);

        foreach (array_keys(self::REQUIRED_HEADERS) as $header) {
            if (str_contains($contentLower, strtolower($header))) {
                $foundHeaders[$header] = true;
            }
        }
    }

    /**
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
}
