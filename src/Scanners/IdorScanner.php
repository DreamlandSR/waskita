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
        '$this->authorize(',
        'can(',
        '->can(',
        '->cannot(',
        '->cant(',
        'auth()->id()',
        'auth()->user()->id',
        'Auth::id()',
        'Auth::user()->id',
        '$request->user()->id',
        'user_id',
        'owner_id',
        'created_by',
        'Policy',
        '->forUser(',
        'abort_if(',
        'abort_unless(',
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
            $results = array_merge($results, $this->scanControllerFile($file, $basePath));
        }

        // 2. Scan Route files untuk model binding tanpa can: middleware
        $routeFiles = $this->getRouteFiles($basePath);
        foreach ($routeFiles as $file) {
            $results = array_merge($results, $this->scanRouteFile($file, $basePath));
        }

        return $results;
    }

    /**
     * Scan satu Controller file untuk aksi resource tanpa authorization.
     *
     * @return AuditResult[]
     */
    private function scanControllerFile(string $filePath, string $basePath): array
    {
        $results = [];
        $content = (string) file_get_contents($filePath);
        $relativePath = $this->getRelativePath($filePath, $basePath);
        $lines = explode("\n", $content);

        // Cari semua method public dalam class
        // Pattern: public function methodName(TypeHint $param, ...)
        $pattern = '/public\s+function\s+(\w+)\s*\(([^)]*)\)/';

        if (! preg_match_all($pattern, $content, $methodMatches, PREG_OFFSET_CAPTURE)) {
            return [];
        }

        foreach ($methodMatches[0] as $i => $match) {
            $methodName = $methodMatches[1][$i][0];
            $params = $methodMatches[2][$i][0];
            $methodOffset = $match[1];
            $methodLine = substr_count(substr($content, 0, $methodOffset), "\n") + 1;

            // Hanya audit resource actions atau methods yang menerima model/id parameter
            $isResourceAction = in_array(strtolower($methodName), self::RESOURCE_ACTIONS, true);
            $hasModelParam = $this->hasModelOrIdParam($params);

            if (! $isResourceAction && ! $hasModelParam) {
                continue;
            }

            // Ambil method body (dari signature sampai bracket penutup di level yang benar)
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

        // Cek direct query tanpa scope user
        $results = array_merge($results, $this->scanDirectObjectQuery($content, $relativePath, $lines));

        return $results;
    }

    /**
     * Cek apakah parameter berisi model type-hint atau $id.
     */
    private function hasModelOrIdParam(string $params): bool
    {
        // Type-hinted model: Post $post, Berita $berita, User $user
        if (preg_match('/(?:^|,\s*)(?!Request|int|string|array|float|bool)([A-Z]\w+)\s+\$\w+/', $params)) {
            return true;
        }

        // Variable $id, $postId, $userId, etc.
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

        // Type-hinted models
        if (preg_match_all('/(?:^|,\s*)([A-Z]\w+)\s+(\$\w+)/', $params, $matches)) {
            for ($i = 0; $i < count($matches[0]); $i++) {
                $type = $matches[1][$i];
                $var = $matches[2][$i];
                if (! in_array($type, ['Request', 'FormRequest', 'int', 'string', 'array'], true)) {
                    $descriptions[] = "{$type} {$var}";
                }
            }
        }

        // $id params
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

        // Pola: Model::findOrFail($id) atau Model::find($id)
        $pattern = '/\b([A-Z]\w+)::(findOrFail|find)\s*\(\s*\$(\w*id\w*)\s*\)/i';

        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $i => $match) {
                $offset = $match[1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;

                // Cek konteks sekitar (5 baris setelah) untuk auth check
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
     * @return AuditResult[]
     */
    private function scanRouteFile(string $filePath, string $basePath): array
    {
        $results = [];
        $content = (string) file_get_contents($filePath);
        $relativePath = $this->getRelativePath($filePath, $basePath);
        $lines = explode("\n", $content);

        // Pola route dengan parameter: Route::get('/posts/{post}', ...)
        // Termasuk edit, update, destroy, show
        $pattern = '/Route::(get|post|put|patch|delete)\s*\(\s*[\'"]([^"\']*\{[^}]+\}[^"\']*)[\'"](?:\s*,\s*([^;]+))/i';

        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $i => $match) {
                $offset = $match[1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;
                $uri = $matches[2][$i][0];
                $routeDefinition = $matches[3][$i][0] ?? '';

                // Cek konteks baris sekitar untuk middleware can: atau middleware('can:')
                $contextStart = max(0, $lineNumber - 2);
                $contextEnd = min(count($lines), $lineNumber + 4);
                $contextLines = array_slice($lines, $contextStart, $contextEnd - $contextStart);
                $context = implode("\n", $contextLines);

                $hasCanMiddleware = (bool) preg_match(
                    '/middleware\s*\(\s*.*(?:can:|auth|authorize|gate)/i',
                    $context . $routeDefinition
                );

                if (! $hasCanMiddleware) {
                    $snippet = trim($lines[$lineNumber - 1] ?? $match[0]);

                    $results[] = new AuditResult(
                        ruleId: 'IDOR_ROUTE_MISSING_CAN',
                        category: 'idor',
                        severity: AuditResult::SEVERITY_MEDIUM,
                        title: "Route Model Binding Without 'can:' Middleware: {$uri}",
                        description: "Route '{$uri}' menggunakan parameter binding tanpa middleware 'can:' untuk otorisasi. Pastikan controller atau policy menangani otorisasi data.",
                        file: $relativePath,
                        line: $lineNumber,
                        codeSnippet: $snippet,
                        suggestion: "Tambahkan ->middleware('can:view,post') atau definisikan Laravel Policy pada resource controller.",
                        cveRef: 'CWE-639'
                    );
                }
            }
        }

        return $results;
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

        // Cari file route lainnya
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
