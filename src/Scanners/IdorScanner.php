<?php

declare(strict_types=1);

namespace Waskita\Security\Scanners;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\ContainerBootstrapper;
use Waskita\Security\Core\LaravelSecurityDictionary;
use Waskita\Security\Core\ScannerInterface;

/**
 * IdorScanner - Mendeteksi kerentanan Insecure Direct Object References (IDOR).
 *
 * Mendukung 2 mode pemindaian:
 * 1. Live Router & Container Reflection (Akurat 100%):
 *    - Membaca mapping aksi controller ke middleware peran aplikasi.
 *    - Memeriksa otorisasi FormRequest::authorize() via PHP Reflection.
 *    - Memeriksa $this->authorizeResource() pada controller.
 * 2. Static File Analysis (Fallback):
 *    - Analisis sintaksis statis file controller, form request, & route.
 *
 * Pemeriksaan:
 * 1. Controller actions yang menerima model/ID tanpa pengecekan authorization atau role middleware.
 * 2. FormRequest::authorize() yang mengembalikan 'true' tanpa proteksi izin/policy.
 * 3. Route model binding tanpa middleware 'can:' atau policy.
 * 4. Direct query Model::findOrFail($id) tanpa verifikasi kepemilikan data pada konteks non-admin.
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

    /** @var string[] Pattern authorization yang valid di dalam method body */
    private const AUTH_PATTERNS = LaravelSecurityDictionary::AUTHORIZATION_PATTERNS;

    public function getName(): string
    {
        return 'IDOR Scanner';
    }

    public function getDescription(): string
    {
        return 'Mendeteksi potensi IDOR: controller actions tanpa authorization check, FormRequest::authorize() return true tanpa izin, route tanpa middleware can:, dan direct object query tanpa verifikasi kepemilikan.';
    }

    public function scan(string $basePath, array $config = []): array
    {
        $results = [];

        // 1. Dapatkan mapping middleware dari live router via ContainerBootstrapper jika Laravel aktif
        $actionMiddlewareMap = [];
        $bootstrapper = ContainerBootstrapper::detect($basePath);
        $isLive = $bootstrapper !== null && $bootstrapper->isAvailable() && $bootstrapper->getRouter() !== null;

        if ($isLive) {
            try {
                $router = $bootstrapper->getRouter();
                foreach ($router->getRoutes() as $route) {
                    $action = $route->getActionName();
                    if ($action && str_contains($action, '@')) {
                        $actionMiddlewareMap[$action] = array_unique(array_merge(
                            $actionMiddlewareMap[$action] ?? [],
                            $route->gatherMiddleware()
                        ));
                    }
                }
            } catch (\Throwable) {
                $isLive = false;
            }
        }

        // 2. Scan Controller files
        $controllerFiles = $this->findPhpFiles($basePath . '/app/Http/Controllers');
        foreach ($controllerFiles as $file) {
            $results = array_merge($results, $this->scanControllerFile($file, $basePath, $config, $actionMiddlewareMap));
        }

        // 3. Scan Routes
        if ($isLive) {
            $results = array_merge($results, $this->scanLiveRoutes($basePath, $config));
        } else {
            $routeFiles = $this->getRouteFiles($basePath);
            foreach ($routeFiles as $file) {
                $results = array_merge($results, $this->scanRouteFile($file, $basePath, $config));
            }
        }

        return $results;
    }

    /**
     * Scan satu Controller file untuk aksi resource tanpa authorization.
     *
     * @param array<string, mixed> $config
     * @param array<string, string[]> $actionMiddlewareMap
     * @return AuditResult[]
     */
    private function scanControllerFile(string $filePath, string $basePath, array $config = [], array $actionMiddlewareMap = []): array
    {
        $results = [];
        $content = (string) file_get_contents($filePath);
        $relativePath = $this->getRelativePath($filePath, $basePath);
        $lines = explode("\n", $content);

        $adminPatterns = $config['idor']['admin_controllers'] ?? ['*Admin*', '*AdminController', 'App\\Http\\Controllers\\Admin\\*'];
        $publicActions = $config['idor']['public_actions'] ?? ['show', 'download', 'preview', 'index'];
        $roleMiddlewares = $config['idor']['role_middlewares'] ?? ['admin', 'auth', 'role:*', 'permission:*', 'can:*'];

        $isAdminController = $this->matchesPattern($relativePath, $adminPatterns);

        // Jika controller adalah controller admin berdasarkan nama, seluruh aksi merupakan hak administratif
        if ($isAdminController) {
            return [];
        }

        $fullClassName = $this->extractFullClassName($content);

        // Cek apakah controller menggunakan $this->authorizeResource(...)
        $hasAuthorizeResource = (bool) preg_match('/\$this->authorizeResource\s*\(/', $content);

        // Cari semua method public dalam class
        $pattern = '/public\s+function\s+(\w+)\s*\(([^)]*)\)/';

        if (! preg_match_all($pattern, $content, $methodMatches, PREG_OFFSET_CAPTURE)) {
            return [];
        }

        // Daftar method yang terverifikasi aman untuk dilewati oleh scanDirectObjectQuery
        $safeMethods = [];

        foreach ($methodMatches[0] as $i => $match) {
            $methodName = $methodMatches[1][$i][0];
            $params = $methodMatches[2][$i][0];
            $methodOffset = (int) $match[1];
            $methodLine = substr_count(substr($content, 0, $methodOffset), "\n") + 1;

            // Jika aksi termasuk aksi publik read-only, abaikan cek kepemilikan
            if (in_array(strtolower($methodName), $publicActions, true)) {
                $safeMethods[] = $methodName;
                continue;
            }

            // Jika controller menggunakan $this->authorizeResource(...) dan method ini adalah resource action standar
            $isResourceAction = in_array(strtolower($methodName), self::RESOURCE_ACTIONS, true);
            if ($hasAuthorizeResource && $isResourceAction) {
                $safeMethods[] = $methodName;
                continue;
            }

            // Jika aksi sudah terpasang middleware peran di router (misal: 'admin', 'role:*')
            $actionKey = $fullClassName . '@' . $methodName;
            $appliedMiddlewares = $actionMiddlewareMap[$actionKey] ?? [];

            if ($this->hasRoleMiddleware($appliedMiddlewares, $roleMiddlewares)) {
                $safeMethods[] = $methodName;
                continue;
            }

            // Hanya audit resource actions atau methods yang menerima model/id parameter
            $hasModelParam = $this->hasModelOrIdParam($params);

            if (! $isResourceAction && ! $hasModelParam) {
                continue;
            }

            // Ambil method body
            $methodBody = $this->extractMethodBody($content, $methodOffset);

            if ($methodBody === null) {
                continue;
            }

            // 1. Cek apakah ada authorization check di method body
            $hasAuthCheck = $this->hasAuthorizationCheck($methodBody);

            // 2. Jika tidak ada di method body, periksa FormRequest::authorize() via Reflection & Static Fallback
            $formReqInfo = [
                'has_form_request' => false,
                'request_class' => null,
                'is_authorized' => false,
                'returns_true_only' => false,
                'reason' => '',
            ];

            if (! $hasAuthCheck) {
                $formReqInfo = $this->inspectFormRequestAuthorization($fullClassName, $methodName, $params, $content, $basePath);
                if ($formReqInfo['is_authorized']) {
                    $hasAuthCheck = true;
                }
            }

            if ($hasAuthCheck) {
                $safeMethods[] = $methodName;
            } else {
                $snippet = trim($lines[$methodLine - 1] ?? $match[0]);
                $paramDesc = $hasModelParam ? $this->describeModelParams($params) : 'resource action';

                if ($formReqInfo['has_form_request'] && $formReqInfo['returns_true_only']) {
                    $desc = "Method '{$methodName}' menerima model/ID ({$paramDesc}) dan menginjeksi FormRequest '{$formReqInfo['request_class']}', tetapi method authorize() mengembalikan nilai 'true' tanpa pemeriksaan izin/kebijakan, serta tidak ada authorization check di controller.";
                    $fix = "Implementasikan otorisasi pada {$formReqInfo['request_class']}::authorize() (misal: return \$this->user()->can('update', \$this->route(...))) atau gunakan \$this->authorize() di controller.";
                } else {
                    $desc = "Method '{$methodName}' menerima parameter model/ID ({$paramDesc}) namun tidak ditemukan authorization check (authorize(), Gate, policy, FormRequest::authorize(), atau verifikasi kepemilikan user_id).";
                    $fix = "Tambahkan \$this->authorize('update', \$model), implementasikan FormRequest::authorize(), atau gunakan Laravel Policy / Gate. Alternatif: scope query via auth()->user()->posts()->findOrFail(\$id).";
                }

                $results[] = new AuditResult(
                    ruleId: 'IDOR_MISSING_AUTHORIZATION',
                    category: 'idor',
                    severity: AuditResult::SEVERITY_HIGH,
                    title: "Potential IDOR: Missing Authorization in {$methodName}()",
                    description: $desc,
                    file: $relativePath,
                    line: $methodLine,
                    codeSnippet: $snippet,
                    suggestion: $fix,
                    cveRef: 'CWE-639'
                );
            }
        }

        // Cek direct query tanpa scope user (menghindari false positive pada aksi ber-middleware admin atau safe methods)
        $results = array_merge($results, $this->scanDirectObjectQuery($content, $relativePath, $lines, $fullClassName, $actionMiddlewareMap, $roleMiddlewares, $safeMethods));

        return $results;
    }

    /**
     * Memeriksa otorisasi FormRequest pada parameter method controller.
     * Mendukung Reflection (Container/Class loaded) dan Fallback Statis (File parsing).
     *
     * @return array{has_form_request: bool, request_class: ?string, is_authorized: bool, returns_true_only: bool, reason: string}
     */
    private function inspectFormRequestAuthorization(
        string $fullClassName,
        string $methodName,
        string $params,
        string $controllerContent,
        string $basePath
    ): array {
        // 1. Coba via Reflection jika class controller ter-load
        if ($fullClassName !== '' && class_exists($fullClassName)) {
            try {
                $refMethod = new \ReflectionMethod($fullClassName, $methodName);
                foreach ($refMethod->getParameters() as $param) {
                    $type = $param->getType();
                    if (! $type instanceof \ReflectionNamedType || $type->isBuiltin()) {
                        continue;
                    }

                    $paramClassName = $type->getName();
                    if (! class_exists($paramClassName)) {
                        continue;
                    }

                    if (is_subclass_of($paramClassName, 'Illuminate\Foundation\Http\FormRequest')) {
                        return $this->inspectFormRequestClass($paramClassName);
                    }
                }
            } catch (\Throwable) {
                // Lanjut ke fallback statis
            }
        }

        // 2. Fallback Statis: Cari tipe parameter yang berakhiran 'Request'
        return $this->inspectFormRequestStatic($params, $controllerContent, $basePath);
    }

    /**
     * Analisis method authorize() pada kelas FormRequest via Reflection.
     *
     * @param class-string $formRequestClass
     * @return array{has_form_request: bool, request_class: string, is_authorized: bool, returns_true_only: bool, reason: string}
     */
    private function inspectFormRequestClass(string $formRequestClass): array
    {
        try {
            $refClass = new \ReflectionClass($formRequestClass);
            if (! $refClass->hasMethod('authorize')) {
                return [
                    'has_form_request' => true,
                    'request_class' => $formRequestClass,
                    'is_authorized' => false,
                    'returns_true_only' => false,
                    'reason' => 'Method authorize() tidak didefinisikan.',
                ];
            }

            $authMethod = $refClass->getMethod('authorize');

            // Jika method authorize() tidak dioverride oleh FormRequest kustom (hanya bawaan framework)
            if ($authMethod->getDeclaringClass()->getName() === 'Illuminate\Foundation\Http\FormRequest') {
                return [
                    'has_form_request' => true,
                    'request_class' => $formRequestClass,
                    'is_authorized' => false,
                    'returns_true_only' => false,
                    'reason' => 'Menggunakan bawaan base FormRequest::authorize().',
                ];
            }

            $fileName = $authMethod->getFileName();
            if ($fileName && file_exists($fileName)) {
                $body = $this->extractMethodContent($fileName, $authMethod);
                if ($body !== null) {
                    if ($this->hasAuthorizationCheck($body)) {
                        return [
                            'has_form_request' => true,
                            'request_class' => $formRequestClass,
                            'is_authorized' => true,
                            'returns_true_only' => false,
                            'reason' => 'FormRequest::authorize() memiliki logika otorisasi.',
                        ];
                    }

                    $stripped = preg_replace('/\s+/', '', strtolower($body));
                    if (str_contains($stripped, 'returnfalse;')) {
                        return [
                            'has_form_request' => true,
                            'request_class' => $formRequestClass,
                            'is_authorized' => true,
                            'returns_true_only' => false,
                            'reason' => 'FormRequest::authorize() menolak akses secara default (return false).',
                        ];
                    }

                    if (str_contains($stripped, 'returntrue;')) {
                        return [
                            'has_form_request' => true,
                            'request_class' => $formRequestClass,
                            'is_authorized' => false,
                            'returns_true_only' => true,
                            'reason' => 'FormRequest::authorize() mengembalikan true tanpa validasi izin.',
                        ];
                    }
                }
            }
        } catch (\Throwable) {
            // Abaikan kesalahan reflection
        }

        return [
            'has_form_request' => true,
            'request_class' => $formRequestClass,
            'is_authorized' => false,
            'returns_true_only' => false,
            'reason' => 'Tidak dapat memverifikasi otorisasi FormRequest.',
        ];
    }

    /**
     * Fallback analisis statis untuk mendeteksi FormRequest dan membaca authorize() dari file.
     *
     * @return array{has_form_request: bool, request_class: ?string, is_authorized: bool, returns_true_only: bool, reason: string}
     */
    private function inspectFormRequestStatic(string $params, string $controllerContent, string $basePath): array
    {
        // Cari typehint parameter seperti (UpdateBeritaRequest $request)
        if (! preg_match('/(?:^|,\s*)([A-Z]\w*Request)\s+\$\w+/', $params, $match)) {
            return [
                'has_form_request' => false,
                'request_class' => null,
                'is_authorized' => false,
                'returns_true_only' => false,
                'reason' => '',
            ];
        }

        $requestShortName = $match[1];
        if (in_array($requestShortName, ['Request', 'FormRequest'], true)) {
            return [
                'has_form_request' => false,
                'request_class' => null,
                'is_authorized' => false,
                'returns_true_only' => false,
                'reason' => '',
            ];
        }

        // Resolusi namespace dari use statement
        $targetFile = null;
        if (preg_match('/use\s+([^;]+?\\\\' . preg_quote($requestShortName, '/') . ');/', $controllerContent, $useMatch)) {
            $fullRequestClass = trim($useMatch[1]);
            $relativeClassPath = str_replace(['App\\', '\\'], ['', '/'], $fullRequestClass) . '.php';
            $candidate = $basePath . '/app/' . $relativeClassPath;
            if (file_exists($candidate)) {
                $targetFile = $candidate;
            }
        }

        if ($targetFile === null) {
            // Default path convention: app/Http/Requests/{Name}.php
            $defaultCandidate = $basePath . '/app/Http/Requests/' . $requestShortName . '.php';
            if (file_exists($defaultCandidate)) {
                $targetFile = $defaultCandidate;
            }
        }

        if ($targetFile !== null && file_exists($targetFile)) {
            $reqContent = (string) file_get_contents($targetFile);
            if (preg_match('/public\s+function\s+authorize\s*\([^)]*\)/', $reqContent, $authMatches, PREG_OFFSET_CAPTURE)) {
                $authOffset = (int) $authMatches[0][1];
                $authBody = $this->extractMethodBody($reqContent, $authOffset);

                if ($authBody !== null) {
                    if ($this->hasAuthorizationCheck($authBody)) {
                        return [
                            'has_form_request' => true,
                            'request_class' => $requestShortName,
                            'is_authorized' => true,
                            'returns_true_only' => false,
                            'reason' => 'FormRequest::authorize() memiliki logika otorisasi (statis).',
                        ];
                    }

                    $stripped = preg_replace('/\s+/', '', strtolower($authBody));
                    if (str_contains($stripped, 'returntrue;')) {
                        return [
                            'has_form_request' => true,
                            'request_class' => $requestShortName,
                            'is_authorized' => false,
                            'returns_true_only' => true,
                            'reason' => 'FormRequest::authorize() mengembalikan true tanpa validasi izin (statis).',
                        ];
                    }

                    if (str_contains($stripped, 'returnfalse;')) {
                        return [
                            'has_form_request' => true,
                            'request_class' => $requestShortName,
                            'is_authorized' => true,
                            'returns_true_only' => false,
                            'reason' => 'FormRequest::authorize() menolak akses default (statis).',
                        ];
                    }
                }
            }
        }

        return [
            'has_form_request' => true,
            'request_class' => $requestShortName,
            'is_authorized' => false,
            'returns_true_only' => false,
            'reason' => 'FormRequest terdeteksi tetapi tidak ditemukan logika otorisasi valid.',
        ];
    }

    /**
     * Memindai rute langsung dari Laravel Route Collection (Container-aware).
     *
     * @param array<string, mixed> $config
     * @return AuditResult[]
     */
    private function scanLiveRoutes(string $basePath, array $config = []): array
    {
        $results = [];
        $bootstrapper = ContainerBootstrapper::detect($basePath);
        if ($bootstrapper === null || !$bootstrapper->isAvailable() || $bootstrapper->getRouter() === null) {
            return [];
        }

        $router = $bootstrapper->getRouter();
        $routes = $router->getRoutes();

        $roleMiddlewares = $config['idor']['role_middlewares'] ?? ['admin', 'auth', 'role:*', 'permission:*', 'can:*'];
        $publicActions = $config['idor']['public_actions'] ?? ['show', 'download', 'preview', 'index'];

        foreach ($routes as $route) {
            $uri = $route->uri();
            $params = $route->parameterNames();

            // Hanya audit route yang memiliki parameter dinamis (contoh: /berita/{berita})
            if (empty($params)) {
                continue;
            }

            // Abaikan jika parameter hanya slug atau kategori publik
            $isOnlySlugOrCategory = true;
            foreach ($params as $param) {
                if (! in_array(strtolower($param), ['slug', 'kategori', 'category', 'year', 'month'], true)) {
                    $isOnlySlugOrCategory = false;
                    break;
                }
            }
            if ($isOnlySlugOrCategory) {
                continue;
            }

            // Jika rute berada di bawah prefix admin/ atau static storage
            $cleanUri = ltrim($uri, '/');
            if (str_starts_with($cleanUri, 'admin/') || str_starts_with($cleanUri, 'storage/')) {
                continue;
            }

            // Cek middleware yang terpasang pada route
            $middlewares = $route->gatherMiddleware();
            if ($this->hasRoleMiddleware($middlewares, $roleMiddlewares)) {
                continue;
            }

            // Jika method GET dan merupakan aksi publik read-only
            $methods = array_map('strtolower', $route->methods());
            $isGet = in_array('get', $methods, true);

            $action = $route->getActionName();
            $actionMethod = str_contains($action, '@') ? explode('@', $action)[1] : '';

            if ($isGet && in_array(strtolower($actionMethod), $publicActions, true)) {
                continue;
            }

            $results[] = new AuditResult(
                ruleId: 'IDOR_ROUTE_MISSING_CAN',
                category: 'idor',
                severity: AuditResult::SEVERITY_MEDIUM,
                title: "Route Model Binding Without 'can:' Middleware: /{$uri}",
                description: "Route '/{$uri}' menggunakan parameter binding tanpa middleware 'can:' atau proteksi peran (role/admin).",
                file: 'routes/web.php',
                line: 1,
                codeSnippet: "Route::" . ($methods[0] ?? 'any') . "('/{$uri}', '{$action}')",
                suggestion: "Tambahkan ->middleware('can:view,model') atau tempatkan di dalam grup middleware peran yang sesuai.",
                cveRef: 'CWE-639'
            );
        }

        return $results;
    }

    /**
     * Cek apakah daftar middleware mengandung middleware peran atau 'can:'.
     *
     * @param string[] $appliedMiddlewares
     * @param string[] $roleMiddlewares
     */
    private function hasRoleMiddleware(array $appliedMiddlewares, array $roleMiddlewares): bool
    {
        foreach ($appliedMiddlewares as $applied) {
            if (! is_string($applied)) {
                continue;
            }

            $lowerApplied = strtolower($applied);

            if (str_starts_with($lowerApplied, 'can:') || str_starts_with($lowerApplied, 'role:') || str_starts_with($lowerApplied, 'permission:')) {
                return true;
            }

            if (in_array($lowerApplied, ['admin', 'auth', 'role', 'permission'], true)) {
                return true;
            }

            foreach ($roleMiddlewares as $pattern) {
                if (fnmatch(strtolower($pattern), $lowerApplied, FNM_CASEFOLD)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Ekstrak namespace dan nama class dari isi file PHP.
     */
    private function extractFullClassName(string $content): string
    {
        $ns = '';
        $cls = '';

        if (preg_match('/namespace\s+([^;]+);/', $content, $nsMatch)) {
            $ns = trim($nsMatch[1]);
        }

        if (preg_match('/class\s+(\w+)/', $content, $clsMatch)) {
            $cls = trim($clsMatch[1]);
        }

        return ($ns && $cls) ? "{$ns}\\{$cls}" : $cls;
    }

    /**
     * Dapatkan nama method pembungkus untuk suatu posisi offset di dalam kode.
     */
    private function getEnclosingMethodName(string $content, int $offset): ?string
    {
        $pattern = '/public\s+function\s+(\w+)\s*\(/';
        if (preg_match_all($pattern, substr($content, 0, $offset), $matches, PREG_OFFSET_CAPTURE)) {
            $lastMatch = end($matches[1]);
            return $lastMatch[0] ?? null;
        }

        return null;
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
     * Ekstrak teks konten method dari file berdasarkan objek ReflectionMethod.
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
     * Cek apakah method body mengandung authorization check.
     */
    private function hasAuthorizationCheck(string $methodBody): bool
    {
        return LaravelSecurityDictionary::hasAuthorizationCheck($methodBody);
    }

    /**
     * Scan direct query Model::findOrFail($id) tanpa verifikasi.
     *
     * @param string[] $lines
     * @param array<string, string[]> $actionMiddlewareMap
     * @param string[] $roleMiddlewares
     * @param string[] $safeMethods
     * @return AuditResult[]
     */
    private function scanDirectObjectQuery(
        string $content,
        string $relativePath,
        array $lines,
        string $fullClassName = '',
        array $actionMiddlewareMap = [],
        array $roleMiddlewares = [],
        array $safeMethods = []
    ): array {
        $results = [];

        $pattern = '/\b([A-Z]\w+)::(findOrFail|find)\s*\(\s*\$(\w*id\w*)\s*\)/i';

        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $i => $match) {
                $offset = (int) $match[1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;

                $enclosingMethod = $this->getEnclosingMethodName($content, $offset);

                // Jika method pembungkus sudah terverifikasi aman (misal memiliki FormRequest::authorize())
                if ($enclosingMethod !== null && in_array($enclosingMethod, $safeMethods, true)) {
                    continue;
                }

                // Cek apakah method pembungkus query ini dilindungi oleh middleware admin/role
                if ($fullClassName !== '' && ! empty($actionMiddlewareMap) && $enclosingMethod !== null) {
                    $actionKey = $fullClassName . '@' . $enclosingMethod;
                    $appliedMiddlewares = $actionMiddlewareMap[$actionKey] ?? [];
                    if ($this->hasRoleMiddleware($appliedMiddlewares, $roleMiddlewares)) {
                        // Query terjadi di dalam method administratif terproteksi
                        continue;
                    }
                }

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
     * Scan file route untuk model binding tanpa can: middleware (Fallback statis).
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

        $pattern = '/Route::(get|post|put|patch|delete)\s*\(\s*[\'"]([^"\'*]*\{[^}]+\}[^"\'*]*)[\'"](?:\s*,\s*([^;]+))/i';

        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $i => $match) {
                $httpMethod = strtolower($matches[1][$i][0]);
                $uri = $matches[2][$i][0];
                $routeDefinition = $matches[3][$i][0] ?? '';
                $offset = (int) $match[1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;

                if (str_contains($uri, '{slug}') || str_contains($uri, '{kategori}') || str_contains($uri, '{category}')) {
                    continue;
                }

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

                if ($httpMethod === 'get' && ! str_starts_with(ltrim($uri, '/'), 'admin/')) {
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
