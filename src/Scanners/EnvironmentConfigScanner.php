<?php

declare(strict_types=1);

namespace Waskita\Security\Scanners;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\ScannerInterface;

/**
 * EnvironmentConfigScanner - Memeriksa konfigurasi keamanan file .env dan file config Laravel.
 *
 * Pemeriksaan:
 * 1. APP_DEBUG=true ketika APP_ENV=production -> CRITICAL (CVE-2021-3129 Ignition RCE)
 * 2. APP_KEY kosong, tidak valid, atau default -> CRITICAL
 * 3. SESSION_SECURE_COOKIE false / config('session.secure') false -> MEDIUM
 * 4. SESSION_HTTP_ONLY false / config('session.http_only') false -> HIGH
 * 5. config/app.php debug di-hardcode ke true -> HIGH
 */
class EnvironmentConfigScanner implements ScannerInterface
{
    public function getName(): string
    {
        return 'Environment & Configuration Scanner';
    }

    public function getDescription(): string
    {
        return 'Memeriksa konfigurasi keamanan di .env dan file config (APP_DEBUG di production, APP_KEY, secure cookie, session http_only).';
    }

    public function scan(string $basePath, array $config = []): array
    {
        $results = [];

        // 1. Audit .env file (jika ada)
        $envFile = $basePath . '/.env';
        if (file_exists($envFile)) {
            $results = array_merge($results, $this->scanEnvFile($envFile));
        }

        // 2. Audit config/session.php
        $sessionConfigFile = $basePath . '/config/session.php';
        if (file_exists($sessionConfigFile)) {
            $results = array_merge($results, $this->scanSessionConfig($sessionConfigFile));
        }

        // 3. Audit config/app.php
        $appConfigFile = $basePath . '/config/app.php';
        if (file_exists($appConfigFile)) {
            $results = array_merge($results, $this->scanAppConfig($appConfigFile));
        }

        return $results;
    }

    /**
     * Scan file .env.
     *
     * @return AuditResult[]
     */
    private function scanEnvFile(string $envPath): array
    {
        $results = [];
        $content = (string) file_get_contents($envPath);
        $lines = explode("\n", $content);

        $envVars = $this->parseEnvLines($lines);

        $appEnv = strtolower(trim($envVars['APP_ENV']['value'] ?? 'local'));
        $appDebug = strtolower(trim($envVars['APP_DEBUG']['value'] ?? 'false'));
        $appKey = trim($envVars['APP_KEY']['value'] ?? '');

        // Cek 1: APP_DEBUG=true pada production (CRITICAL - CVE-2021-3129)
        $isProduction = in_array($appEnv, ['production', 'prod', 'live'], true);
        $isDebugOn = in_array($appDebug, ['true', '1', 'on', 'yes'], true);

        if ($isProduction && $isDebugOn) {
            $debugLine = $envVars['APP_DEBUG']['line'] ?? 1;
            $snippet = trim($lines[$debugLine - 1] ?? 'APP_DEBUG=true');

            $results[] = new AuditResult(
                ruleId: 'ENV_APP_DEBUG_PRODUCTION',
                category: 'configuration',
                severity: AuditResult::SEVERITY_CRITICAL,
                title: 'APP_DEBUG=true in Production Environment',
                description: 'APP_DEBUG diaktifkan (true) pada environment production. Ini mengekspos stack trace lengkap, detail database credentials, API keys, dan berpotensi Remote Code Execution (RCE) melalui Laravel Ignition facade.',
                file: '.env',
                line: $debugLine,
                codeSnippet: $snippet,
                suggestion: 'Set APP_DEBUG=false di file .env production segera.',
                cveRef: 'CVE-2021-3129'
            );
        }

        // Cek 2: APP_KEY kosong atau tidak aman (CRITICAL)
        if (empty($appKey)) {
            $keyLine = $envVars['APP_KEY']['line'] ?? 1;
            $results[] = new AuditResult(
                ruleId: 'ENV_APP_KEY_EMPTY',
                category: 'configuration',
                severity: AuditResult::SEVERITY_CRITICAL,
                title: 'Missing APP_KEY in .env',
                description: 'APP_KEY tidak disetel atau kosong di file .env. Enkripsi session, cookies, signed URLs, dan data terenkripsi lainnya tidak berfungsi atau tidak aman.',
                file: '.env',
                line: $keyLine,
                codeSnippet: 'APP_KEY=',
                suggestion: "Jalankan 'php artisan key:generate' untuk membuat Application Key yang aman.",
                cveRef: 'CWE-321'
            );
        } elseif (strlen($appKey) < 16 || $appKey === 'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=') {
            $keyLine = $envVars['APP_KEY']['line'] ?? 1;
            $snippet = trim($lines[$keyLine - 1] ?? $appKey);

            $results[] = new AuditResult(
                ruleId: 'ENV_APP_KEY_WEAK',
                category: 'configuration',
                severity: AuditResult::SEVERITY_CRITICAL,
                title: 'Weak or Default APP_KEY in .env',
                description: 'APP_KEY terlalu pendek atau menggunakan nilai placeholder default. Penyerang dapat mendekripsi session cookie dan memanipulasi data.',
                file: '.env',
                line: $keyLine,
                codeSnippet: $snippet,
                suggestion: "Jalankan 'php artisan key:generate' untuk memperbarui Application Key acak yang kuat.",
                cveRef: 'CWE-321'
            );
        }

        // Cek 3: SESSION_SECURE_COOKIE di .env
        if (isset($envVars['SESSION_SECURE_COOKIE'])) {
            $secureVal = strtolower(trim($envVars['SESSION_SECURE_COOKIE']['value']));
            if (in_array($secureVal, ['false', '0', 'off', 'no'], true) && $isProduction) {
                $line = $envVars['SESSION_SECURE_COOKIE']['line'];
                $snippet = trim($lines[$line - 1] ?? '');

                $results[] = new AuditResult(
                    ruleId: 'ENV_SESSION_SECURE_FALSE',
                    category: 'configuration',
                    severity: AuditResult::SEVERITY_MEDIUM,
                    title: 'SESSION_SECURE_COOKIE=false in Production',
                    description: 'SESSION_SECURE_COOKIE dinonaktifkan di environment production. Session cookies akan dikirim melalui HTTP unencrypted, rentan terhadap man-in-the-middle sniffing.',
                    file: '.env',
                    line: $line,
                    codeSnippet: $snippet,
                    suggestion: 'Set SESSION_SECURE_COOKIE=true di .env production agar cookie hanya dikirim via HTTPS.',
                    cveRef: 'CWE-614'
                );
            }
        }

        return $results;
    }

    /**
     * Scan config/session.php.
     *
     * @return AuditResult[]
     */
    private function scanSessionConfig(string $configFile): array
    {
        $results = [];
        $content = (string) file_get_contents($configFile);
        $lines = explode("\n", $content);

        // Cek 'secure' config: jika hardcoded false
        if (preg_match('/[\'"]secure[\'"]\s*=>\s*(false|null)\s*,/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $offset = $match[0][1];
            $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;
            $snippet = trim($lines[$lineNumber - 1] ?? $match[0][0]);

            $results[] = new AuditResult(
                ruleId: 'CONFIG_SESSION_SECURE_HARDCODED_FALSE',
                category: 'configuration',
                severity: AuditResult::SEVERITY_MEDIUM,
                title: "Insecure Session Cookie: 'secure' is Hardcoded to false",
                description: "Nilai 'secure' pada config/session.php di-hardcode ke false atau null tanpa fallback env('SESSION_SECURE_COOKIE', true). Cookie session dapat ditransmisikan via plaintext HTTP.",
                file: 'config/session.php',
                line: $lineNumber,
                codeSnippet: $snippet,
                suggestion: "Gunakan 'secure' => env('SESSION_SECURE_COOKIE', true) agar cookie hanya dikirim via HTTPS di production.",
                cveRef: 'CWE-614'
            );
        }

        // Cek 'http_only' config: jika false
        if (preg_match('/[\'"]http_only[\'"]\s*=>\s*false\s*,/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $offset = $match[0][1];
            $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;
            $snippet = trim($lines[$lineNumber - 1] ?? $match[0][0]);

            $results[] = new AuditResult(
                ruleId: 'CONFIG_SESSION_HTTP_ONLY_FALSE',
                category: 'configuration',
                severity: AuditResult::SEVERITY_HIGH,
                title: "Insecure Session Cookie: 'http_only' is Set to false",
                description: "Nilai 'http_only' pada config/session.php diset ke false. JavaScript dapat membaca cookie session pengguna, sehingga serangan XSS dapat langsung mencuri token session.",
                file: 'config/session.php',
                line: $lineNumber,
                codeSnippet: $snippet,
                suggestion: "Pastikan 'http_only' => true di config/session.php.",
                cveRef: 'CWE-1004'
            );
        }

        // Cek 'same_site' config: jika null atau none
        if (preg_match('/[\'"]same_site[\'"]\s*=>\s*(?:null|[\'"]none[\'"])\s*,/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $offset = $match[0][1];
            $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;
            $snippet = trim($lines[$lineNumber - 1] ?? $match[0][0]);

            $results[] = new AuditResult(
                ruleId: 'CONFIG_SESSION_SAMESITE_NONE',
                category: 'configuration',
                severity: AuditResult::SEVERITY_MEDIUM,
                title: "Weak SameSite Cookie Policy: 'same_site' is null or 'none'",
                description: "Nilai 'same_site' pada config/session.php diset ke null atau 'none'. Ini meningkatkan risiko serangan Cross-Site Request Forgery (CSRF).",
                file: 'config/session.php',
                line: $lineNumber,
                codeSnippet: $snippet,
                suggestion: "Ubah 'same_site' => 'lax' atau 'strict' di config/session.php.",
                cveRef: 'CWE-1275'
            );
        }

        return $results;
    }

    /**
     * Scan config/app.php untuk hardcoded debug mode.
     *
     * @return AuditResult[]
     */
    private function scanAppConfig(string $configFile): array
    {
        $results = [];
        $content = (string) file_get_contents($configFile);
        $lines = explode("\n", $content);

        // Cek 'debug' => true yang hardcoded (tanpa env())
        if (preg_match('/[\'"]debug[\'"]\s*=>\s*true\s*,/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $offset = $match[0][1];
            $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;
            $snippet = trim($lines[$lineNumber - 1] ?? $match[0][0]);

            $results[] = new AuditResult(
                ruleId: 'CONFIG_APP_DEBUG_HARDCODED',
                category: 'configuration',
                severity: AuditResult::SEVERITY_HIGH,
                title: "APP_DEBUG is Hardcoded to true in config/app.php",
                description: "Nilai 'debug' pada config/app.php di-hardcode ke true tanpa menggunakan env('APP_DEBUG'). Mode debug akan selalu aktif terlepas dari setting .env.",
                file: 'config/app.php',
                line: $lineNumber,
                codeSnippet: $snippet,
                suggestion: "Ubah menjadi 'debug' => (bool) env('APP_DEBUG', false).",
                cveRef: 'CWE-200'
            );
        }

        return $results;
    }

    /**
     * Parse line .env menjadi associative array [KEY => ['value' => val, 'line' => lineNum]].
     *
     * @param string[] $lines
     * @return array<string, array{value: string, line: int}>
     */
    private function parseEnvLines(array $lines): array
    {
        $vars = [];

        foreach ($lines as $index => $line) {
            $trimmed = trim($line);

            // Lewati komentar atau baris kosong
            if ($trimmed === '' || str_starts_with($trimmed, '#')) {
                continue;
            }

            if (str_contains($trimmed, '=')) {
                $parts = explode('=', $trimmed, 2);
                $key = trim($parts[0]);
                $val = trim($parts[1] ?? '');

                // Bersihkan quote pembungkus jika ada
                if ((str_starts_with($val, '"') && str_ends_with($val, '"')) ||
                    (str_starts_with($val, "'") && str_ends_with($val, "'"))) {
                    $val = substr($val, 1, -1);
                }

                $vars[$key] = [
                    'value' => $val,
                    'line' => $index + 1,
                ];
            }
        }

        return $vars;
    }
}
