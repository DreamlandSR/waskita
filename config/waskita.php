<?php

declare(strict_types=1);

use Waskita\Security\Scanners\CsrfScanner;
use Waskita\Security\Scanners\EnvironmentConfigScanner;
use Waskita\Security\Scanners\IdorScanner;
use Waskita\Security\Scanners\MassAssignmentScanner;
use Waskita\Security\Scanners\RateLimitScanner;
use Waskita\Security\Scanners\SecurityHeaderScanner;
use Waskita\Security\Scanners\SqlInjectionScanner;
use Waskita\Security\Scanners\XssScanner;

return [

    /*
    |--------------------------------------------------------------------------
    | Severity Threshold
    |--------------------------------------------------------------------------
    |
    | The minimum severity level for findings to be included in reports.
    | Options: 'critical', 'high', 'medium', 'low', 'info'
    |
    */

    'severity_threshold' => env('WASKITA_SEVERITY_THRESHOLD', 'low'),

    /*
    |--------------------------------------------------------------------------
    | Fail On Severity
    |--------------------------------------------------------------------------
    |
    | If any finding meets or exceeds this severity level, the audit command
    | will exit with code 1 (failure). Useful for CI/CD pipelines.
    | Options: 'critical', 'high', 'medium', 'low', 'info'
    |
    */

    'fail_on' => env('WASKITA_FAIL_ON', 'high'),

    /*
    |--------------------------------------------------------------------------
    | Strictness Level
    |--------------------------------------------------------------------------
    |
    | Mode ketat audit scanner:
    | - 'pedantic': Melaporkan semua temuan termasuk INFO/peringatan minor.
    | - 'actionable' (default): Hanya melaporkan temuan dengan risiko nyata.
    | - 'minimal': Hanya melaporkan temuan HIGH dan CRITICAL.
    |
    */

    'strictness_level' => env('WASKITA_STRICTNESS_LEVEL', 'actionable'),

    /*
    |--------------------------------------------------------------------------
    | Trusted View Helpers (XSS Whitelist)
    |--------------------------------------------------------------------------
    |
    | Daftar helper/class yang diizinkan untuk di-echo unescaped ({!! ... !!})
    | tanpa dianggap celah XSS (misal untuk merender static icon SVG).
    |
    */

    'trusted_view_helpers' => [
        'Icons::get',
        'svg',
        'heroicon',
        'icon',
        'feather',
    ],

    /*
    |--------------------------------------------------------------------------
    | Enabled Scanners
    |--------------------------------------------------------------------------
    |
    | List of scanner classes to run during an audit.
    |
    */

    'scanners' => [
        CsrfScanner::class,
        EnvironmentConfigScanner::class,
        IdorScanner::class,
        MassAssignmentScanner::class,
        RateLimitScanner::class,
        SecurityHeaderScanner::class,
        SqlInjectionScanner::class,
        XssScanner::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | Ignored Paths
    |--------------------------------------------------------------------------
    |
    | Directories that should be excluded from scanning. Paths are relative
    | to the project root.
    |
    */

    'ignore_paths' => [
        'vendor',
        'node_modules',
        'storage',
        'bootstrap/cache',
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom Rules Path
    |--------------------------------------------------------------------------
    |
    | Directory containing custom YAML security rule definitions.
    | Set to null to disable custom rules.
    |
    */

    'custom_rules_path' => function_exists('base_path') ? base_path('rules/security') : 'rules/security',

    /*
    |--------------------------------------------------------------------------
    | Sensitive Database Columns
    |--------------------------------------------------------------------------
    |
    | Column names that should be treated as sensitive. The MassAssignment
    | scanner will flag models exposing these columns via $fillable.
    |
    */

    'sensitive_columns' => [
        'role',
        'is_admin',
        'admin',
        'password',
        'remember_token',
        'permissions',
    ],

    /*
    |--------------------------------------------------------------------------
    | Sensitive Route Segments
    |--------------------------------------------------------------------------
    |
    | Route URI segments that indicate security-sensitive endpoints.
    | The RouteScanner / RateLimitScanner will verify proper protection.
    |
    */

    'sensitive_routes' => [
        'login',
        'masuk',
        'password',
        'lupa-kata-sandi',
        'register',
        'daftar',
    ],

    /*
    |--------------------------------------------------------------------------
    | Required Security Headers
    |--------------------------------------------------------------------------
    |
    | HTTP response headers that must be present. The SecurityHeaderScanner
    | checks for these and flags any that are missing.
    |
    */

    'required_headers' => [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Referrer-Policy',
    ],

    /*
    |--------------------------------------------------------------------------
    | XSS Scanner Allowlist & Safe Patterns
    |--------------------------------------------------------------------------
    |
    | Daftarkan helper/callable atau regex pattern yang menghasilkan output
    | HTML/SVG aman dalam {!! ... !!} agar tidak ditandai sebagai false positive.
    |
    */

    'xss' => [
        // Method/helper atau class yang diizinkan menggunakan {!! !!}
        'safe_callables' => [
            'Icons::get',
            'svg',
            'heroicon',
            'icon',
            'feather',
        ],

        // Regex ekspresi yang dianggap aman
        'safe_patterns' => [
            // '/Icons::get\(.+?\)/',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | IDOR & Role Context Configuration
    |--------------------------------------------------------------------------
    |
    | Menyesuaikan audit IDOR dengan alur bisnis aplikasi.
    | Controller admin dan aksi publik tidak akan disalahartikan sebagai IDOR.
    |
    */

    'idor' => [
        // Controller yang beroperasi dengan hak superuser/admin (wildcard * didukung)
        'admin_controllers' => [
            '*Admin*',
            '*AdminController',
            'App\\Http\\Controllers\\Admin\\*',
        ],

        // Aksi resource yang bersifat read-only untuk publik
        'public_actions' => [
            'show',
            'download',
            'preview',
            'index',
        ],

        // Middleware penanda akses sudah dibatasi peran
        'role_middlewares' => [
            'admin',
            'auth',
            'role:*',
            'permission:*',
            'can:*',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Inline Annotations (@waskita-ignore)
    |--------------------------------------------------------------------------
    |
    | Mengaktifkan pembacaan komentar direktif inline seperti:
    | // @waskita-ignore [RULE_ID]
    | untuk mengecualikan baris kode yang sudah diverifikasi aman secara bisnis.
    |
    */

    'ignore_annotations' => [
        'enabled' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Baseline Configuration (waskita-baseline.json)
    |--------------------------------------------------------------------------
    |
    | Baseline mencatat seluruh temuan celah keamanan yang saat ini sudah ada
    | ke dalam file waskita-baseline.json via perintah:
    |   php artisan waskita:baseline
    |
    | Saat aktif, audit CI/CD hanya akan gagal jika ada celah keamanan BARU
    | yang diperkenalkan setelah baseline dibuat.
    |
    */

    'baseline' => [
        'enabled' => true,
        'path' => 'waskita-baseline.json',
    ],

];
