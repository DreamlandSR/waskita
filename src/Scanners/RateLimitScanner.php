<?php

declare(strict_types=1);

namespace Waskita\Security\Scanners;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\ScannerInterface;

/**
 * RateLimitScanner - Memeriksa keberadaan Rate Limiting (throttle middleware) pada endpoint sensitif.
 *
 * Mendukung 2 mode pemindaian:
 * 1. Live Router Container (Akurat 100%): Membaca langsung route collection & middleware yang di-compile Laravel.
 * 2. Static File Analysis (Fallback): Untuk pengujian terisolasi tanpa container Laravel.
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
        'masuk' => 'Brute Force / Credential Stuffing',
        'register' => 'Spam Account Creation / Flooding',
        'daftar' => 'Spam Account Creation / Flooding',
        'password/reset' => 'Password Reset Poisoning / Flooding',
        'password/email' => 'Email Flooding / Denial of Service',
        'forgot-password' => 'Email Flooding / Denial of Service',
        'lupa-kata-sandi' => 'Email Flooding / Denial of Service',
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
        // 1. Prioritaskan Live Router Discovery jika berjalan di dalam container Laravel
        $container = \class_exists(\Illuminate\Container\Container::class) ? \Illuminate\Container\Container::getInstance() : null;
        if ($container !== null && $container->bound('router')) {
            try {
                return $this->scanLiveRoutes($basePath, $config, $container->make('router'));
            } catch (\Throwable) {
                // Fallback ke analisis file statis jika live router gagal
            }
        }

        // 2. Fallback: Static Route Files Analysis
        return $this->scanStaticRoutes($basePath, $config);
    }

    /**
     * Memindai rute langsung dari Laravel Route Collection (Container-aware).
     *
     * @param array<string, mixed> $config
     * @param mixed $router
     * @return AuditResult[]
     */
    private function scanLiveRoutes(string $basePath, array $config = [], mixed $router = null): array
    {
        $results = [];
        if ($router === null) {
            $router = \Illuminate\Container\Container::getInstance()->make('router');
        }
        $routes = $router->getRoutes();

        $sensitiveRoutes = array_unique(array_merge(
            array_keys(self::SENSITIVE_KEYWORDS),
            $config['sensitive_routes'] ?? []
        ));

        foreach ($routes as $route) {
            $uri = $route->uri();
            $methods = array_map('strtolower', $route->methods());

            // Abaikan method HEAD
            $methods = array_values(array_diff($methods, ['head']));

            $matchedKeyword = null;
            $riskDesc = 'Brute Force / Flooding Attack';

            foreach ($sensitiveRoutes as $keyword) {
                $pattern = '#(?:^|/)' . preg_quote($keyword, '#') . '(?:$|/)#i';
                if (preg_match($pattern, trim($uri, '/'))) {
                    $matchedKeyword = $keyword;
                    $riskDesc = self::SENSITIVE_KEYWORDS[$keyword] ?? 'Brute Force / Flooding Attack';
                    break;
                }
            }

            if ($matchedKeyword === null) {
                continue;
            }

            // Jika hanya method GET, abaikan kecuali endpoint verifikasi OTP/Token
            $isWriteMethod = (bool) array_intersect($methods, ['post', 'put', 'patch', 'delete']);
            if (! $isWriteMethod && ! in_array($matchedKeyword, ['otp', '2fa', 'verify', 'reset-password'], true)) {
                continue;
            }

            // Dapatkan seluruh middleware yang terpasang pada route (termasuk dari group)
            $middlewares = $route->gatherMiddleware();
            $hasThrottle = false;

            foreach ($middlewares as $mw) {
                if (is_string($mw) && (
                    str_starts_with($mw, 'throttle')
                    || str_contains(strtolower($mw), 'ratelimit')
                )) {
                    $hasThrottle = true;
                    break;
                }
            }

            // Lokasi file dan baris
            $action = $route->getActionName();
            $filePath = 'routes/web.php';
            $lineNumber = 1;
            $snippet = "Route::" . ($methods[0] ?? 'any') . "('/{$uri}', '{$action}')";

            if (str_contains($action, '@')) {
                [$controllerClass, $methodName] = explode('@', $action);
                if (class_exists($controllerClass) && method_exists($controllerClass, $methodName)) {
                    try {
                        $refMethod = new \ReflectionMethod($controllerClass, $methodName);
                        $controllerFile = $refMethod->getFileName();
                        if ($controllerFile) {
                            $filePath = $this->getRelativePath($controllerFile, $basePath);
                            $lineNumber = $refMethod->getStartLine() ?: 1;
                            $snippet = "public function {$methodName}(...) in {$filePath}:{$lineNumber}";

                            // Cek jika controller menangani rate limiting secara manual (RateLimiter::hit)
                            $methodContent = $this->extractMethodContent($controllerFile, $refMethod);
                            if ($methodContent && (
                                str_contains($methodContent, 'RateLimiter::')
                                || str_contains($methodContent, 'RateLimited')
                            )) {
                                $hasThrottle = true;
                            }
                        }
                    } catch (\Throwable) {
                        // Tetap gunakan fallback rute
                    }
                }
            }

            if (! $hasThrottle) {
                $httpMethodUpper = strtoupper(implode('|', $methods));

                $results[] = new AuditResult(
                    ruleId: 'RATE_LIMIT_SENSITIVE_ENDPOINT',
                    category: 'rate_limiting',
                    severity: AuditResult::SEVERITY_HIGH,
                    title: "Missing Rate Limiting (throttle) on Sensitive Route: [{$httpMethodUpper}] '/{$uri}'",
                    description: "Endpoint sensitif '/{$uri}' tidak memiliki middleware throttle. Rentan terhadap serangan {$riskDesc} (CWE-307 / CWE-799).",
                    file: $filePath,
                    line: $lineNumber,
                    codeSnippet: $snippet,
                    suggestion: "Tambahkan middleware ->middleware('throttle:6,1') atau 'throttle:login' pada route ini atau group route-nya.",
                    cveRef: 'CWE-307'
                );
            }
        }

        return $results;
    }

    /**
     * Scan file rute statis (Fallback jika container tidak tersedia).
     *
     * @param array<string, mixed> $config
     * @return AuditResult[]
     */
    private function scanStaticRoutes(string $basePath, array $config = []): array
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

        $pattern = '/Route::(post|match|any|get)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,/i';

        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $i => $match) {
                $httpMethod = strtolower($matches[1][$i][0]);
                $uri = $matches[2][$i][0];
                $offset = (int) $match[1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;

                $matchedKeyword = null;
                $riskDesc = '';

                foreach (self::SENSITIVE_KEYWORDS as $keyword => $risk) {
                    $kwPattern = '#(?:^|/)' . preg_quote($keyword, '#') . '(?:$|/)#i';
                    if (preg_match($kwPattern, trim($uri, '/'))) {
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

                $routeStatement = $this->extractRouteStatement($content, $offset);
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
     * Ekstrak isi method controller untuk mencari pemanggilan RateLimiter manual.
     */
    private function extractMethodContent(string $filePath, \ReflectionMethod $ref): ?string
    {
        if (! file_exists($filePath)) {
            return null;
        }

        $startLine = $ref->getStartLine();
        $endLine = $ref->getEndLine();
        if (! $startLine || ! $endLine) {
            return null;
        }

        $lines = file($filePath, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            return null;
        }

        return implode("\n", array_slice($lines, $startLine - 1, $endLine - $startLine + 1));
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
        $startPos = max(0, $offset - 1500);
        $before = substr($content, $startPos, $offset - $startPos);

        if (preg_match('/Route::middleware\s*\(\s*\[[^\]]*throttle[^\]]*\]\s*\)\s*->group/i', $before)
            || preg_match('/Route::prefix\([^)]+\)->middleware\s*\(\s*\[[^\]]*throttle[^\]]*\]\s*\)/i', $before)) {
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
