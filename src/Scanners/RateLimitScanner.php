<?php

declare(strict_types=1);

namespace Waskita\Security\Scanners;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\ScannerInterface;

/**
 * RateLimitScanner - Memeriksa keberadaan Rate Limiting (throttle middleware) pada endpoint sensitif.
 *
 * Endpoint yang diaudit:
 * - Login / Otentikasi
 * - Registrasi akun
 * - Password reset / Forgot password
 * - Form kontak / Kirim pesan publik
 * - OTP / Verifikasi 2FA
 * - API Auth / Token generation
 */
class RateLimitScanner implements ScannerInterface
{
    /** @var array<string, string> Keywords endpoint sensitif beserta kategori risikonya */
    private const SENSITIVE_KEYWORDS = [
        'login' => 'Brute Force / Credential Stuffing',
        'register' => 'Spam Account Creation / Flooding',
        'password/reset' => 'Password Reset Poisoning / Flooding',
        'password/email' => 'Email Flooding / Denial of Service',
        'forgot-password' => 'Email Flooding / Denial of Service',
        'reset-password' => 'Brute Force Token Attack',
        'kontak' => 'Form Spam / Mail Flooding',
        'contact' => 'Form Spam / Mail Flooding',
        'otp' => 'OTP Brute Force Attack',
        'verify' => 'Verification Token Brute Force',
        'two-factor' => '2FA Brute Force Attack',
        '2fa' => '2FA Brute Force Attack',
    ];

    public function getName(): string
    {
        return 'Rate Limit Scanner';
    }

    public function getDescription(): string
    {
        return 'Mendeteksi endpoint sensitif (login, register, reset password, kontak, OTP) yang belum dilindungi oleh throttle middleware.';
    }

    public function scan(string $basePath, array $config = []): array
    {
        $results = [];

        $routeFiles = $this->getRouteFiles($basePath);

        foreach ($routeFiles as $file) {
            $results = array_merge($results, $this->scanRouteFile($file, $basePath));
        }

        return $results;
    }

    /**
     * Scan satu file route untuk endpoint sensitif tanpa throttle middleware.
     *
     * @return AuditResult[]
     */
    private function scanRouteFile(string $filePath, string $basePath): array
    {
        $results = [];
        $content = (string) file_get_contents($filePath);
        $relativePath = $this->getRelativePath($filePath, $basePath);
        $lines = explode("\n", $content);

        // Cari definisi route: Route::post('uri', ...), Route::match([...], 'uri', ...)
        // Fokus utama pada POST/PUT/PATCH (submission endpoint)
        $pattern = '/Route::(post|match|any|get)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,/i';

        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $i => $match) {
                $httpMethod = strtolower($matches[1][$i][0]);
                $uri = $matches[2][$i][0];
                $offset = $match[1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;

                // Cek apakah URI cocok dengan salah satu keyword sensitif
                $matchedKeyword = null;
                $riskDesc = '';

                foreach (self::SENSITIVE_KEYWORDS as $keyword => $risk) {
                    if (str_contains(strtolower($uri), $keyword)) {
                        // Khusus GET: hanya flag jika keyword adalah otp, verify, atau password/reset
                        if ($httpMethod === 'get' && ! in_array($keyword, ['otp', '2fa', 'verify'], true)) {
                            continue;
                        }

                        $matchedKeyword = $keyword;
                        $riskDesc = $risk;
                        break;
                    }
                }

                if ($matchedKeyword === null) {
                    continue;
                }

                // Periksa apakah route memiliki middleware throttle
                // Ambil konteks: dari line ini hingga akhir statement (titik koma ';')
                $routeStatement = $this->extractRouteStatement($content, $offset);

                // Periksa juga apakah ada group enclosing dengan throttle di atasnya
                $hasThrottle = $this->hasThrottleMiddleware($routeStatement) ||
                               $this->isInsideThrottledGroup($content, $offset);

                if (! $hasThrottle) {
                    $snippet = trim($lines[$lineNumber - 1] ?? $match[0]);

                    $results[] = new AuditResult(
                        ruleId: 'RATE_LIMIT_SENSITIVE_ENDPOINT',
                        category: 'rate_limiting',
                        severity: AuditResult::SEVERITY_HIGH,
                        title: "Missing Rate Limiting (throttle) on Sensitive Route: '{$uri}'",
                        description: "Endpoint sensitif '{$uri}' tidak memiliki middleware throttle. Rentan terhadap serangan {$riskDesc} (CWE-307 / CWE-799).",
                        file: $relativePath,
                        line: $lineNumber,
                        codeSnippet: $snippet,
                        suggestion: "Tambahkan middleware ->middleware('throttle:6,1') atau 'throttle:login' pada route ini atau group route-nya.",
                        cveRef: 'CWE-307'
                    );
                }
            }
        }

        return $results;
    }

    /**
     * Ekstrak statement route lengkap dari offset hingga titik koma.
     */
    private function extractRouteStatement(string $content, int $offset): string
    {
        $semicolonPos = strpos($content, ';', $offset);
        if ($semicolonPos === false) {
            $semicolonPos = min($offset + 500, strlen($content));
        }

        return substr($content, $offset, $semicolonPos - $offset + 1);
    }

    /**
     * Cek apakah statement mengandung throttle middleware.
     */
    private function hasThrottleMiddleware(string $statement): bool
    {
        return (bool) preg_match('/throttle(?::|\b)/i', $statement)
            || str_contains($statement, 'RateLimiter')
            || str_contains($statement, 'RateLimited');
    }

    /**
     * Cek apakah route berada di dalam Route::middleware(['throttle:...'])->group(...)
     */
    private function isInsideThrottledGroup(string $content, int $offset): bool
    {
        // Ambil potongan teks sebelum offset (sampai 1500 karakter ke belakang)
        $startPos = max(0, $offset - 1500);
        $before = substr($content, $startPos, $offset - $startPos);

        // Cari group dengan throttle
        if (preg_match('/Route::middleware\s*\(\s*\[[^\]]*throttle[^\]]*\]\s*\)\s*->group/i', $before)
            || preg_match('/Route::prefix\([^)]+\)->middleware\s*\(\s*\[[^\]]*throttle[^\]]*\]\s*\)/i', $before)) {
            // Hitung kurung kurawal untuk melihat apakah group masih terbuka
            $openBraces = substr_count($before, '{');
            $closeBraces = substr_count($before, '}');

            return $openBraces > $closeBraces;
        }

        return false;
    }

    /**
     * Dapatkan daftar file route yang ada di project.
     *
     * @return string[]
     */
    private function getRouteFiles(string $basePath): array
    {
        $files = [];
        $candidates = [
            $basePath . '/routes/web.php',
            $basePath . '/routes/api.php',
            $basePath . '/routes/auth.php',
        ];

        foreach ($candidates as $file) {
            if (file_exists($file)) {
                $files[] = $file;
            }
        }

        // Cari file route lainnya di bawah routes/
        $routesDir = $basePath . '/routes';
        if (is_dir($routesDir)) {
            $all = glob($routesDir . '/*.php');
            if ($all) {
                foreach ($all as $f) {
                    if (! in_array($f, $files, true)) {
                        $files[] = $f;
                    }
                }
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
