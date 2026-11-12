<?php

declare(strict_types=1);

namespace Waskita\Security\Core;

/**
 * LaravelSecurityDictionary - Kamus Aturan Keamanan Khusus Ekosistem Laravel.
 *
 * Mensentralisasi pemetaan Source, Sink, Sanitizer, Safe Contracts,
 * dan mekanisme keamanan bawaan Laravel agar seluruh scanner konsisten
 * dan tidak menduplikasi pola keamanan.
 */
class LaravelSecurityDictionary
{
    /**
     * Sumber data masukan pengguna mentah (Sources / Tainted Inputs).
     */
    public const USER_INPUT_SOURCES = [
        '$request->',
        'request()->',
        'request(',
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$input',
        '$query',
        'Input::get(',
        'Request::input(',
        'Request::get(',
    ];

    /**
     * Bentuk data request yang SUDAH divalidasi atau aman (Safe / Whitelisted Inputs).
     */
    public const VALIDATED_REQUEST_SOURCES = [
        '$request->validated()',
        'request()->validated()',
        '$request->safe()',
        'request()->safe()',
        '$request->only(',
        'request()->only(',
        '$request->boolean(',
        '$request->integer(',
        '$request->date(',
    ];

    /**
     * Fungsi sanitasi dan encoding yang mencegah XSS (Sanitizers & Encoders).
     */
    public const XSS_SANITIZERS = [
        'Purifier::clean(',
        'clean(',
        'htmlspecialchars(',
        'htmlentities(',
        'e(',
        'strip_tags(',
        'Str::of(',
        'new HtmlString(',
        'HtmlString(',
        '->toHtml()',
        'toHtml()',
        'number_format(',
        'intval(',
        'floatval(',
        'count(',
        'round(',
        'ceil(',
        'floor(',
        'date(',
        '->format(',
    ];

    /**
     * Interface / Class Contract Laravel yang menandakan objek aman untuk di-render langsung (Htmlable).
     */
    public const HTMLABLE_CONTRACTS = [
        'Illuminate\Contracts\Support\Htmlable',
        'Illuminate\Support\HtmlString',
    ];

    /**
     * Helper render SVG/HTML internal yang aman (Default Safe Callables).
     */
    public const DEFAULT_SAFE_VIEW_HELPERS = [
        'Icons::get',
        'svg',
        'heroicon',
        'icon',
        'feather',
        'blade-icon',
    ];

    /**
     * Atribut HTML event handler yang berbahaya bila diisi ekspresi dinamis.
     */
    public const DANGEROUS_HTML_ATTRIBUTES = [
        'onclick',
        'onload',
        'onerror',
        'onmouseover',
        'onmouseenter',
        'onfocus',
        'onblur',
        'onsubmit',
        'onchange',
        'oninput',
    ];

    /**
     * Method raw query di Eloquent / DB facade (SQL Injection Sinks).
     */
    public const SQL_RAW_SINKS = [
        'DB::raw',
        'whereRaw',
        'orWhereRaw',
        'havingRaw',
        'orHavingRaw',
        'orderByRaw',
        'groupByRaw',
        'selectRaw',
        'DB::select',
        'DB::statement',
        'DB::unprepared',
    ];

    /**
     * Kolom database sensitif yang dilarang dimasukkan ke dalam $fillable Model.
     */
    public const DEFAULT_SENSITIVE_COLUMNS = [
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

    /**
     * Keyword endpoint rute sensitif beserta risiko serangan jika tanpa rate limiting.
     *
     * @var array<string, string>
     */
    public const SENSITIVE_ROUTE_KEYWORDS = [
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

    /**
     * Pola otorisasi yang valid dalam method body controller untuk mitigasi IDOR.
     */
    public const AUTHORIZATION_PATTERNS = [
        'authorize(',
        'Gate::authorize(',
        'Gate::allows(',
        'Gate::denies(',
        'Gate::check(',
        'Gate::inspect(',
        '$this->authorize(',
        '$this->pastikan',
        '$this->check',
        'can(',
        '->can(',
        '->cannot(',
        '->cant(',
        'auth()->id()',
        'auth()->user()',
        'Auth::id()',
        'Auth::user()',
        '$request->user()',
        'user_id',
        'owner_id',
        'created_by',
        'penulis',
        'Policy',
        '->forUser(',
        'abort_if(',
        'abort_unless(',
        'abort(403',
        'abort(401',
        'abort(Response::HTTP_FORBIDDEN',
        'abort(Response::HTTP_UNAUTHORIZED',
    ];

    /**
     * Pola throttle / rate limiting bawaan Laravel.
     */
    public const RATE_LIMIT_PATTERNS = [
        'throttle',
        'RateLimiter::hit',
        'RateLimiter::attempt',
        'RateLimiter::for',
        'RateLimited',
    ];

    /**
     * Periksa apakah sebuah ekspresi mengandung input pengguna mentah (tainted source).
     */
    public static function containsUserInput(string $expression): bool
    {
        foreach (self::USER_INPUT_SOURCES as $source) {
            if (str_contains($expression, $source)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Periksa apakah sebuah ekspresi sudah disanitasi atau dikonversi dengan aman.
     */
    public static function isSanitized(string $expression): bool
    {
        foreach (self::XSS_SANITIZERS as $sanitizer) {
            if (str_contains($expression, $sanitizer)) {
                return true;
            }
        }

        return (bool) preg_match(
            '/(?:Purifier::|\\\\Purifier::)?(?:clean|htmlspecialchars|htmlentities|e|strip_tags)\s*\(|new\s+(?:\\\\?Illuminate\\\\Support\\\\)?HtmlString\s*\(|(?:->|::)toHtml\s*\(/i',
            $expression
        );
    }

    /**
     * Periksa apakah ekspresi merupakan helper/callable yang terdaftar aman atau di-whitelist di config.
     *
     * @param array<string, mixed> $config
     */
    public static function isSafeViewHelper(string $expression, array $config = []): bool
    {
        $safeCallables = array_merge(
            self::DEFAULT_SAFE_VIEW_HELPERS,
            $config['trusted_view_helpers'] ?? [],
            $config['xss']['safe_callables'] ?? []
        );

        $expressionClean = str_replace('\\', '', $expression);

        foreach ($safeCallables as $callable) {
            $callableClean = str_replace('\\', '', $callable);
            if (stripos($expressionClean, $callableClean) !== false) {
                return true;
            }
        }

        $safePatterns = $config['xss']['safe_patterns'] ?? [];
        foreach ($safePatterns as $pattern) {
            if (@preg_match($pattern, $expression)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Periksa apakah ekspresi bernilai literal statis (tanpa variabel dinamis $).
     */
    public static function isStaticLiteral(string $expression): bool
    {
        if (self::containsUserInput($expression)) {
            return false;
        }

        if (! str_contains($expression, '$')) {
            return true;
        }

        // Pemanggilan helper dengan parameter murni literal tanpa variabel
        if (preg_match('/^[A-Za-z0-9_\\\:]+\(\s*(?:[\'"][^\'"]*[\'"]|\d+|true|false|null)(?:\s*,\s*(?:[\'"][^\'"]*[\'"]|\d+|true|false|null))*\s*\)$/i', trim($expression))) {
            return true;
        }

        return false;
    }

    /**
     * Periksa apakah nama kolom termasuk kolom sensitif (Mass Assignment).
     *
     * @param array<string, mixed> $config
     */
    public static function isSensitiveColumn(string $columnName, array $config = []): bool
    {
        $sensitiveColumns = array_unique(array_merge(
            self::DEFAULT_SENSITIVE_COLUMNS,
            $config['sensitive_columns'] ?? []
        ));

        $lowerCol = strtolower(trim($columnName));

        foreach ($sensitiveColumns as $sens) {
            if (strtolower($sens) === $lowerCol) {
                return true;
            }
        }

        return false;
    }

    /**
     * Periksa apakah URI rute mengandung keyword sensitif yang wajib di-throttle.
     *
     * @param array<string, mixed> $config
     * @return array{keyword: string, risk: string}|null
     */
    public static function matchSensitiveRoute(string $uri, array $config = []): ?array
    {
        $keywords = self::SENSITIVE_ROUTE_KEYWORDS;
        $customKeywords = $config['sensitive_routes'] ?? [];

        foreach ($customKeywords as $custom) {
            if (! isset($keywords[$custom])) {
                $keywords[$custom] = 'Brute Force / Flooding Attack';
            }
        }

        $cleanUri = trim($uri, '/');

        foreach ($keywords as $keyword => $riskDesc) {
            $pattern = '#(?:^|/)' . preg_quote($keyword, '#') . '(?:$|/)#i';
            if (preg_match($pattern, $cleanUri)) {
                return [
                    'keyword' => $keyword,
                    'risk' => $riskDesc,
                ];
            }
        }

        return null;
    }

    /**
     * Periksa apakah string atau middleware mengandung proteksi rate limiting.
     */
    public static function hasRateLimiting(string $statement): bool
    {
        foreach (self::RATE_LIMIT_PATTERNS as $pattern) {
            if (stripos($statement, $pattern) !== false) {
                return true;
            }
        }

        return (bool) preg_match('/throttle(?::|\b)/i', $statement);
    }

    /**
     * Periksa apakah kode method mengandung pola otorisasi.
     */
    public static function hasAuthorizationCheck(string $code): bool
    {
        foreach (self::AUTHORIZATION_PATTERNS as $pattern) {
            if (str_contains($code, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Filter severity berdasarkan strictness_level:
     * - 'pedantic': semua severity dilaporkan
     * - 'actionable' (default): LOW, MEDIUM, HIGH, CRITICAL dilaporkan
     * - 'minimal': hanya HIGH dan CRITICAL
     *
     * @param array<string, mixed> $config
     */
    public static function isAllowedByStrictness(string $severity, array $config = []): bool
    {
        if (! isset($config['strictness_level'])) {
            return true;
        }

        $level = strtolower((string) $config['strictness_level']);
        $severityUpper = strtoupper($severity);

        return match ($level) {
            'minimal' => in_array($severityUpper, [AuditResult::SEVERITY_CRITICAL, AuditResult::SEVERITY_HIGH], true),
            'actionable' => in_array($severityUpper, [
                AuditResult::SEVERITY_CRITICAL,
                AuditResult::SEVERITY_HIGH,
                AuditResult::SEVERITY_MEDIUM,
                AuditResult::SEVERITY_LOW,
            ], true),
            'pedantic' => true,
            default => true,
        };
    }
}
