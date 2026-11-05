<?php

declare(strict_types=1);

namespace Waskita\Security\Scanners;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\ScannerInterface;

/**
 * IdorScanner - Mendeteksi kerentanan Insecure Direct Object References (IDOR).
 *
 * Pemeriksaan:
 * 1. Controller actions yang menerima model/ID tanpa pengecekan authorization.
 * 2. Route model binding tanpa middleware 'can:' atau policy.
 * 3. Direct query Model::findOrFail($id) tanpa verifikasi kepemilikan data.
 */
class IdorScanner implements ScannerInterface
{
    /** @var string[] Nama method aksi yang umumnya mengandung akses per-resource */
    private const RESOURCE_ACTIONS = [
        'show',
        'edit',
        'update',
        'destroy',
        'delete',
        'download',
        'detail',
        'view',
        'remove',
        'approve',
        'reject',
    ];

    /** @var string[] Pattern authorization yang valid */
    private const AUTH_PATTERNS = [
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

    public function getName(): string
    {
        return 'IDOR Scanner';
    }

    public function getDescription(): string
    {
        return 'Mendeteksi potensi IDOR: controller actions tanpa authorization check, route tanpa middleware can:, dan direct object query tanpa verifikasi kepemilikan.';
    }

    public function scan(string $basePath, array $config = []): array
    {
        $results = [];

        // 1. Scan Controller files
        $controllerFiles = $this->findPhpFiles($basePath . '/app/Http/Controllers');
        foreach ($controllerFiles as $file) {
            $results = array_merge($results, $this->scanControllerFile($file, $basePath, $config));
        }

        // 2. Scan Route files untuk model binding tanpa can: middleware
        $routeFiles = $this->getRouteFiles($basePath);
        foreach ($routeFiles as $file) {
            $results = array_merge($results, $this->scanRouteFile($file, $basePath, $config));
        }

        return $results;
    }

    /**
     * Scan satu Controller file untuk aksi resource tanpa authorization.
     *
     * @param array<string, mixed> $config
     * @return AuditResult[]
     */
    private function scanControllerFile(string $filePath, string $basePath, array $config = []): array
    {
        $results = [];
        $content = (string) file_get_contents($filePath);
        $relativePath = $this->getRelativePath($filePath, $basePath);
        $lines = explode("\n", $content);

        $adminPatterns = $config['idor']['admin_controllers'] ?? ['*Admin*', '*AdminController', 'App\\Http\\Controllers\\Admin\\*'];
        $publicActions = $config['idor']['public_actions'] ?? ['show', 'download', 'preview', 'index'];

        $isAdminController = $this->matchesPattern($relativePath, $adminPatterns);

        // Jika controller adalah controller admin, aksi resource merupakan hak administratif superuser
        if ($isAdminController) {
            return [];
        }

        // Cari semua method public dalam class
        $pattern = '/public\s+function\s+(\w+)\s*\(([^)]*)\)/';

        if (! preg_match_all($pattern, $content, $methodMatches, PREG_OFFSET_CAPTURE)) {
            return [];
        }

        foreach ($methodMatches[0] as $i => $match) {
            $methodName = $methodMatches[1][$i][0];
            $params = $methodMatches[2][$i][0];
            $methodOffset = $match[1];
            $methodLine = substr_count(substr($content, 0, $methodOffset), "\n") + 1;

            // Jika aksi termasuk aksi publik read-only, abaikan cek kepemilikan
            if (in_array(strtolower($methodName), $publicActions, true)) {
                continue;
            }

            // Hanya audit resource actions atau methods yang menerima model/id parameter
            $isResourceAction = in_array(strtolower($methodName), self::RESOURCE_ACTIONS, true);
            $hasModelParam = $this->hasModelOrIdParam($params);

            if (! $isResourceAction && ! $hasModelParam) {
                continue;
            }

            // Ambil method body
            $methodBody = $this->extractMethodBody($content, $methodOffset);

            if ($methodBody === null) {
                continue;
            }

            // Cek apakah ada authorization check di method body
            $hasAuthCheck = $this->hasAuthorizationCheck($methodBody);

            if (! $hasAuthCheck) {
                $snippet = trim($lines[$methodLine - 1] ?? $match[0]);
                $paramDesc = $hasModelParam ? $this->describeModelParams($params) : 'resource action';

                $results[] = new AuditResult(
                    ruleId: 'IDOR_MISSING_AUTHORIZATION',
                    category: 'idor',
                    severity: AuditResult::SEVERITY_HIGH,
                    title: "Potential IDOR: Missing Authorization in {$methodName}()",
                    description: "Method '{$methodName}' menerima parameter model/ID ({$paramDesc}) namun tidak ditemukan authorization check (authorize(), Gate, policy, atau verifikasi kepemilikan user_id).",
                    file: $relativePath,
                    line: $methodLine,
                    codeSnippet: $snippet,
                    suggestion: "Tambahkan \$this->authorize('update', \$model) atau gunakan Laravel Policy / Gate. Alternatif: scope query via auth()->user()->posts()->findOrFail(\$id).",
                    cveRef: 'CWE-639'
                );
            }
        }

        // Cek direct query tanpa scope user (hanya untuk non-admin)
        $results = array_merge($results, $this->scanDirectObjectQuery($content, $relativePath, $lines));

        return $results;
    }

    /**
     * Cek apakah string cocok dengan salah satu pattern (mendukung wildcard *).
     *
     * @param string[] $patterns
     */
    private function matchesPattern(string $value, array $patterns): bool
    {
        $normalizedValue = str_replace('\\', '/', $value);

        foreach ($patterns as $pattern) {
            $normalizedPattern = str_replace('\\', '/', $pattern);
            if (fnmatch($normalizedPattern, $normalizedValue, FNM_CASEFOLD)) {
                return true;
            }
            if (str_contains(strtolower($normalizedValue), strtolower(trim($pattern, '*')))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Cek apakah parameter berisi model type-hint atau $id.
     */
    private function hasModelOrIdParam(string $params): bool
    {
        if (preg_match('/(?:^|,\s*)(?!Request|FormRequest|int|string|array|float|bool)([A-Z]\w+)\s+\$\w+/', $params)) {
            return true;
        }

        if (preg_match('/\$(\w*id\w*)/i', $params)) {
            return true;
        }

        return false;
    }

    /**
     * Deskripsi parameter model yang ditemukan.
     */
    private function describeModelParams(string $params): string
    {
        $descriptions = [];

        if (preg_match_all('/(?:^|,\s*)([A-Z]\w+)\s+(\$\w+)/', $params, $matches)) {
            for ($i = 0; $i < count($matches[0]); $i++) {
                $type = $matches[1][$i];
                $var = $matches[2][$i];
                if (! in_array($type, ['Request', 'FormRequest', 'int', 'string', 'array'], true)) {
                    $descriptions[] = "{$type} {$var}";
                }
            }
        }

        if (preg_match_all('/(\$\w*id\w*)/i', $params, $matches)) {
            foreach ($matches[1] as $var) {
                $descriptions[] = $var;
            }
        }

        return implode(', ', $descriptions) ?: 'unknown';
    }

    /**
     * Ekstrak body method dari opening brace ke closing brace.
     */
    private function extractMethodBody(string $content, int $offset): ?string
    {
        $braceStart = strpos($content, '{', $offset);
        if ($braceStart === false) {
            return null;
        }

        $depth = 0;
        $len = strlen($content);
        for ($i = $braceStart; $i < $len; $i++) {
            if ($content[$i] === '{') {
                $depth++;
            } elseif ($content[$i] === '}') {
                $depth--;
                if ($depth === 0) {
                    return substr($content, $braceStart, $i - $braceStart + 1);
                }
            }
        }

        return null;
    }

    /**
     * Cek apakah method body mengandung authorization check.
     */
    private function hasAuthorizationCheck(string $methodBody): bool
    {
        foreach (self::AUTH_PATTERNS as $pattern) {
            if (str_contains($methodBody, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Scan direct query Model::findOrFail($id) tanpa verifikasi.
     *
     * @return AuditResult[]
     */
    private function scanDirectObjectQuery(string $content, string $relativePath, array $lines): array
    {
        $results = [];

        $pattern = '/\b([A-Z]\w+)::(findOrFail|find)\s*\(\s*\$(\w*id\w*)\s*\)/i';

        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $i => $match) {
                $offset = $match[1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;

                $contextStart = max(0, $lineNumber - 1);
                $contextEnd = min(count($lines), $lineNumber + 8);
                $context = implode("\n", array_slice($lines, $contextStart, $contextEnd - $contextStart));

                if (! $this->hasAuthorizationCheck($context)) {
                    $snippet = trim($lines[$lineNumber - 1] ?? $match[0]);
                    $model = $matches[1][$i][0];
                    $idVar = $matches[3][$i][0];

                    $results[] = new AuditResult(
                        ruleId: 'IDOR_DIRECT_OBJECT_REFERENCE',
                        category: 'idor',
                        severity: AuditResult::SEVERITY_MEDIUM,
                        title: "Direct Object Query Without Auth Scope: {$model}::find(\${$idVar})",
                        description: "Query langsung {$model}::find(\${$idVar}) tanpa verifikasi kepemilikan. Penyerang bisa mengakses data milik user lain dengan mengubah ID di URL.",
                        file: $relativePath,
                        line: $lineNumber,
                        codeSnippet: $snippet,
                        suggestion: "Scope query ke user: auth()->user()->" . lcfirst($model) . "s()->findOrFail(\${$idVar}), atau tambahkan authorization check.",
                        cveRef: 'CWE-639'
                    );
                }
            }
        }

        return $results;
    }

    /**
     * Scan file route untuk model binding tanpa can: middleware.
     *
     * @param array<string, mixed> $config
     * @return AuditResult[]
     */
    private function scanRouteFile(string $filePath, string $basePath, array $config = []): array
    {
        $results = [];
        $content = (string) file_get_contents($filePath);
        $relativePath = $this->getRelativePath($filePath, $basePath);
        $lines = explode("\n", $content);

        // Pola route dengan parameter: Route::get('/posts/{post}', ...)
        $pattern = '/Route::(get|post|put|patch|delete)\s*\(\s*[\'"]([^"\'*]*\{[^}]+\}[^"\'*]*)[\'"](?:\s*,\s*([^;]+))/i';

        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $i => $match) {
                $httpMethod = strtolower($matches[1][$i][0]);
                $uri = $matches[2][$i][0];
                $routeDefinition = $matches[3][$i][0] ?? '';
                $offset = (int) $match[1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;

                // 1. Parameter slug (contoh: /berita/{slug}) umumnya merupakan konten publik
                if (str_contains($uri, '{slug}') || str_contains($uri, '{kategori}') || str_contains($uri, '{category}')) {
                    continue;
                }

                // 2. Cek baris sekitar langsung
                $contextStart = max(0, $lineNumber - 2);
                $contextEnd = min(count($lines), $lineNumber + 4);
                $contextLines = array_slice($lines, $contextStart, $contextEnd - $contextStart);
                $immediateContext = implode("\n", $contextLines) . $routeDefinition;

                $hasRoleOrCan = (bool) preg_match(
                    '/middleware\s*\(\s*.*(?:can:|auth|authorize|admin|role|penulis|permission)/i',
                    $immediateContext
                );

                if ($hasRoleOrCan) {
                    continue;
                }

                // 3. Cek apakah route berada di dalam enclosing group yang dilindungi role/auth
                $enclosingGroups = $this->getEnclosingGroups($content, $offset);
                $isInsideProtectedGroup = false;
                foreach ($enclosingGroups as $group) {
                    if (preg_match('/(?:middleware|prefix).*[\'"](admin|auth|penulis|role|can:|permission)/i', $group)) {
                        $isInsideProtectedGroup = true;
                        break;
                    }
                }

                if ($isInsideProtectedGroup) {
                    continue;
                }

                // 4. Jika method GET dan merupakan aksi publik (bukan admin)
                if ($httpMethod === 'get' && ! str_starts_with(ltrim($uri, '/'), 'admin/')) {
                    // Akses read-only publik seperti /informasi/{informasi}
                    continue;
                }

                $snippet = trim($lines[$lineNumber - 1] ?? $match[0]);

                $results[] = new AuditResult(
                    ruleId: 'IDOR_ROUTE_MISSING_CAN',
                    category: 'idor',
                    severity: AuditResult::SEVERITY_MEDIUM,
                    title: "Route Model Binding Without 'can:' Middleware: {$uri}",
                    description: "Route '{$uri}' menggunakan parameter binding tanpa middleware 'can:' atau proteksi grup untuk otorisasi.",
                    file: $relativePath,
                    line: $lineNumber,
                    codeSnippet: $snippet,
                    suggestion: "Tambahkan ->middleware('can:view,post') atau tempatkan di dalam grup middleware peran yang sesuai.",
                    cveRef: 'CWE-639'
                );
            }
        }

        return $results;
    }

    /**
     * Dapatkan statement pembuka grup yang melingkupi posisi offset saat ini.
     *
     * @return string[]
     */
    private function getEnclosingGroups(string $content, int $offset): array
    {
        $groups = [];
        $depth = 0;
        $i = $offset - 1;

        while ($i >= 0) {
            $char = $content[$i];
            if ($char === '}') {
                $depth++;
            } elseif ($char === '{') {
                if ($depth > 0) {
                    $depth--;
                } else {
                    // Blok pembuka yang melingkupi offset
                    $stmtStart = max(0, (int) strrpos(substr($content, 0, $i), ';'));
                    $stmt = trim(substr($content, $stmtStart, $i - $stmtStart));
                    if (str_contains($stmt, 'Route::') || str_contains($stmt, 'group(')) {
                        $groups[] = $stmt;
                    }
                }
            }
            $i--;
        }

        return $groups;
    }

    /**
     * Dapatkan daftar file route.
     *
     * @return string[]
     */
    private function getRouteFiles(string $basePath): array
    {
        $files = [];
        $candidates = [
            $basePath . '/routes/web.php',
            $basePath . '/routes/api.php',
        ];

        foreach ($candidates as $file) {
            if (file_exists($file)) {
                $files[] = $file;
            }
        }

        $routesDir = $basePath . '/routes';
        if (is_dir($routesDir)) {
            $allRouteFiles = glob($routesDir . '/*.php');
            if ($allRouteFiles) {
                foreach ($allRouteFiles as $rf) {
                    if (! in_array($rf, $files, true)) {
                        $files[] = $rf;
                    }
                }
            }
        }

        return $files;
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

    private function getRelativePath(string $fullPath, string $basePath): string
    {
        $base = rtrim($basePath, '/') . '/';
        if (str_starts_with($fullPath, $base)) {
            return substr($fullPath, strlen($base));
        }

        return $fullPath;
    }
}
