<?php

declare(strict_types=1);

namespace Waskita\Security\Core;

/**
 * RouteContextResolver - Menghubungkan Relasi Rute -> Middleware -> Controller -> FormRequest.
 *
 * Pipeline Context Flow yang menyatukan informasi keamanan dari seluruh lapisan Laravel:
 * 1. Route Registration (URI, HTTP methods, route name, parameter binding)
 * 2. Middleware Stack (auth, throttle, role, can, csrf exceptions)
 * 3. Controller Action (class, method, parameter type-hints)
 * 4. FormRequest Authorization (authorize() method body analysis)
 *
 * Mendukung 2 mode:
 * - Live Container (via ContainerBootstrapper): Resolusi route akurat 100% dari compiled router
 * - Static File Analysis (Fallback): Parsing file routes/*.php dan controller tanpa container
 */
class RouteContextResolver
{
    /** @var RouteContext[] Cache resolved contexts */
    private array $resolvedContexts = [];

    private bool $isResolved = false;

    public function __construct(
        private readonly ?ContainerBootstrapper $bootstrapper = null,
        private readonly ?AstAnalyzer $astAnalyzer = null,
    ) {}

    /**
     * Buat instance resolver dari base path project Laravel.
     *
     * @param string $basePath Root directory project Laravel
     */
    public static function fromBasePath(string $basePath): self
    {
        return new self(
            bootstrapper: ContainerBootstrapper::detect($basePath),
            astAnalyzer: new AstAnalyzer(),
        );
    }

    /**
     * Resolve seluruh konteks rute dari project Laravel.
     *
     * @param string $basePath Root directory project Laravel
     * @param array<string, mixed> $config Konfigurasi waskita
     * @return RouteContext[]
     */
    public function resolveAll(string $basePath, array $config = []): array
    {
        if ($this->isResolved) {
            return $this->resolvedContexts;
        }

        $this->resolvedContexts = [];

        // 1. Prioritaskan Live Container Resolution
        if ($this->bootstrapper !== null && $this->bootstrapper->isAvailable() && $this->bootstrapper->getRouter() !== null) {
            try {
                $this->resolvedContexts = $this->resolveFromLiveRouter($basePath, $config);
                $this->isResolved = true;

                return $this->resolvedContexts;
            } catch (\Throwable) {
                // Fallback ke static analysis
            }
        }

        // 2. Fallback: Static File Parsing
        $this->resolvedContexts = $this->resolveFromStaticFiles($basePath, $config);
        $this->isResolved = true;

        return $this->resolvedContexts;
    }

    /**
     * Cari RouteContext untuk controller action tertentu.
     *
     * @param string $controllerClass FQCN controller (misal: 'App\Http\Controllers\UserController')
     * @param string $actionMethod Nama method (misal: 'store')
     */
    public function findContextForAction(string $controllerClass, string $actionMethod): ?RouteContext
    {
        $identifier = "{$controllerClass}@{$actionMethod}";

        foreach ($this->resolvedContexts as $ctx) {
            if ($ctx->getActionIdentifier() === $identifier) {
                return $ctx;
            }
        }

        return null;
    }

    /**
     * Cari RouteContext berdasarkan URI dan HTTP method.
     *
     * @param string $uri URI rute (misal: 'login', 'api/users/{user}')
     * @param string $httpMethod HTTP method (default: 'GET')
     */
    public function findContextForUri(string $uri, string $httpMethod = 'GET'): ?RouteContext
    {
        $normalizedUri = ltrim($uri, '/');
        $upperMethod = strtoupper($httpMethod);

        foreach ($this->resolvedContexts as $ctx) {
            if (ltrim($ctx->uri, '/') === $normalizedUri && in_array($upperMethod, array_map('strtoupper', $ctx->methods), true)) {
                return $ctx;
            }
        }

        return null;
    }

    /**
     * Dapatkan semua rute yang dilindungi oleh middleware auth atau role.
     *
     * @return RouteContext[]
     */
    public function getProtectedRoutes(): array
    {
        return array_values(array_filter(
            $this->resolvedContexts,
            static fn (RouteContext $ctx): bool => $ctx->isAuthenticated() || $ctx->hasRoleOrPermission()
        ));
    }

    /**
     * Dapatkan semua rute publik (tanpa middleware auth).
     *
     * @return RouteContext[]
     */
    public function getPublicRoutes(): array
    {
        return array_values(array_filter(
            $this->resolvedContexts,
            static fn (RouteContext $ctx): bool => !$ctx->isAuthenticated() && !$ctx->hasRoleOrPermission()
        ));
    }

    /**
     * Dapatkan semua rute sensitif tanpa throttle (untuk RateLimitScanner).
     *
     * @return RouteContext[]
     */
    public function getSensitiveRoutesWithoutThrottle(): array
    {
        return array_values(array_filter(
            $this->resolvedContexts,
            static function (RouteContext $ctx): bool {
                if ($ctx->hasThrottle()) {
                    return false;
                }

                $match = LaravelSecurityDictionary::matchSensitiveRoute($ctx->uri);
                if ($match === null) {
                    return false;
                }

                // Hanya POST/PUT/DELETE kecuali endpoint OTP/verify
                if (!$ctx->isWriteAction()) {
                    $keyword = $match['keyword'];
                    if (!in_array($keyword, ['otp', '2fa', 'verify', 'reset-password'], true)) {
                        return false;
                    }
                }

                return true;
            }
        ));
    }

    /**
     * Dapatkan semua rute dengan model binding tanpa proteksi can/role (untuk IdorScanner).
     *
     * @return RouteContext[]
     */
    public function getUnprotectedModelBindingRoutes(): array
    {
        return array_values(array_filter(
            $this->resolvedContexts,
            static fn (RouteContext $ctx): bool => $ctx->hasUnprotectedModelBinding() && !$ctx->isAdminRoute()
        ));
    }

    // =========================================================================
    // Live Container Resolution
    // =========================================================================

    /**
     * Resolve konteks rute dari Laravel router yang aktif.
     *
     * @param array<string, mixed> $config
     * @return RouteContext[]
     */
    private function resolveFromLiveRouter(string $basePath, array $config = []): array
    {
        $contexts = [];
        $router = $this->bootstrapper->getRouter();
        if ($router === null) {
            return [];
        }

        foreach ($router->getRoutes() as $route) {
            $uri = $route->uri();
            $methods = $route->methods();
            $middlewares = [];

            try {
                $gathered = $route->gatherMiddleware();
                $middlewares = array_values(array_filter($gathered, 'is_string'));
            } catch (\Throwable) {
                // Abaikan
            }

            $action = $route->getActionName();
            $controller = null;
            $actionMethod = null;
            $sourceFile = null;
            $sourceLine = null;

            if ($action !== null && $action !== 'Closure') {
                if (str_contains($action, '@')) {
                    [$controller, $actionMethod] = explode('@', $action, 2);
                } else {
                    $controller = $action;
                    $actionMethod = '__invoke';
                }

                // Resolve source file dan line via Reflection
                if ($controller !== null && $actionMethod !== null) {
                    try {
                        if (class_exists($controller) && method_exists($controller, $actionMethod)) {
                            $ref = new \ReflectionMethod($controller, $actionMethod);
                            $sourceFile = $this->getRelativePath($ref->getFileName() ?: '', $basePath);
                            $sourceLine = $ref->getStartLine() ?: null;
                        }
                    } catch (\Throwable) {
                        // Abaikan
                    }
                }
            }

            // Resolve FormRequest pada parameter controller
            $formRequestClass = null;
            $formRequestAuthorized = null;

            if ($controller !== null && $actionMethod !== null) {
                [$formRequestClass, $formRequestAuthorized] = $this->resolveFormRequest(
                    $controller, $actionMethod, $basePath
                );
            }

            $contexts[] = new RouteContext(
                uri: $uri,
                methods: $methods,
                middlewares: $middlewares,
                controller: $controller,
                action: $actionMethod,
                name: $route->getName(),
                parameters: $route->parameterNames(),
                formRequestClass: $formRequestClass,
                formRequestAuthorized: $formRequestAuthorized,
                sourceFile: $sourceFile,
                sourceLine: $sourceLine,
            );
        }

        return $contexts;
    }

    // =========================================================================
    // Static File Resolution
    // =========================================================================

    /**
     * Resolve konteks rute dari file route statis dan controller.
     *
     * @param array<string, mixed> $config
     * @return RouteContext[]
     */
    private function resolveFromStaticFiles(string $basePath, array $config = []): array
    {
        $contexts = [];
        $routeFiles = $this->getRouteFiles($basePath);

        foreach ($routeFiles as $file) {
            $contexts = array_merge($contexts, $this->parseStaticRouteFile($file, $basePath, $config));
        }

        return $contexts;
    }

    /**
     * Parse satu file route statis dan extract RouteContext.
     *
     * @param array<string, mixed> $config
     * @return RouteContext[]
     */
    private function parseStaticRouteFile(string $filePath, string $basePath, array $config = []): array
    {
        $contexts = [];
        $content = @file_get_contents($filePath);
        if ($content === false) {
            return [];
        }

        $relativePath = $this->getRelativePath($filePath, $basePath);
        $lines = explode("\n", $content);

        // Parse route definitions: Route::get|post|put|patch|delete|match|any('uri', ...)
        $routePattern = '/Route::(get|post|put|patch|delete|match|any|resource|apiResource)\s*\(\s*[\'\"]([^\'\"]+)[\'\"]\s*,/i';

        if (!preg_match_all($routePattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            return [];
        }

        foreach ($matches[0] as $i => $match) {
            $httpMethod = strtoupper($matches[1][$i][0]);
            $uri = $matches[2][$i][0];
            $offset = (int) $match[1];
            $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;

            // Tentukan HTTP methods berdasarkan macro
            $methods = match (strtolower($httpMethod)) {
                'resource', 'apiresource' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
                'match' => $this->extractMatchMethods($content, $offset),
                'any' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
                default => [$httpMethod],
            };

            // Extract middleware dari route statement dan enclosing group
            $routeStatement = $this->extractRouteStatement($content, $offset);
            $middlewares = $this->extractStaticMiddleware($routeStatement, $content, $offset);

            // Extract controller dan action dari route definition
            [$controller, $actionMethod] = $this->extractControllerAction($routeStatement, $content, $basePath);

            // Extract parameter bindings dari URI
            $parameters = [];
            if (preg_match_all('/\{(\w+)\??}/', $uri, $paramMatches)) {
                $parameters = $paramMatches[1];
            }

            // Resolve FormRequest
            $formRequestClass = null;
            $formRequestAuthorized = null;
            if ($controller !== null && $actionMethod !== null) {
                [$formRequestClass, $formRequestAuthorized] = $this->resolveFormRequestStatic(
                    $controller, $actionMethod, $content, $basePath
                );
            }

            $contexts[] = new RouteContext(
                uri: $uri,
                methods: $methods,
                middlewares: $middlewares,
                controller: $controller,
                action: $actionMethod,
                name: $this->extractRouteName($routeStatement),
                parameters: $parameters,
                formRequestClass: $formRequestClass,
                formRequestAuthorized: $formRequestAuthorized,
                sourceFile: $relativePath,
                sourceLine: $lineNumber,
            );
        }

        return $contexts;
    }

    // =========================================================================
    // FormRequest Resolution
    // =========================================================================

    /**
     * Resolve FormRequest dari parameter controller method via Reflection.
     *
     * @return array{0: string|null, 1: bool|null} [formRequestClass, isAuthorized]
     */
    private function resolveFormRequest(string $controller, string $method, string $basePath): array
    {
        try {
            if (!class_exists($controller) || !method_exists($controller, $method)) {
                return [null, null];
            }

            $ref = new \ReflectionMethod($controller, $method);
            foreach ($ref->getParameters() as $param) {
                $type = $param->getType();
                if (!$type instanceof \ReflectionNamedType || $type->isBuiltin()) {
                    continue;
                }

                $paramClass = $type->getName();
                if (!class_exists($paramClass)) {
                    continue;
                }

                if (is_subclass_of($paramClass, 'Illuminate\Foundation\Http\FormRequest')) {
                    return [$paramClass, $this->analyzeFormRequestAuthorize($paramClass)];
                }
            }
        } catch (\Throwable) {
            // Abaikan
        }

        return [null, null];
    }

    /**
     * Resolve FormRequest dari static analysis (tanpa Reflection).
     *
     * @return array{0: string|null, 1: bool|null} [formRequestClass, isAuthorized]
     */
    private function resolveFormRequestStatic(
        string $controller,
        string $method,
        string $routeContent,
        string $basePath
    ): array {
        // Cari file controller
        $controllerFile = $this->resolveControllerFile($controller, $basePath);
        if ($controllerFile === null) {
            return [null, null];
        }

        $controllerContent = @file_get_contents($controllerFile);
        if ($controllerContent === false) {
            return [null, null];
        }

        // Cari method signature
        $pattern = '/public\s+function\s+' . preg_quote($method, '/') . '\s*\(([^)]*)\)/';
        if (!preg_match($pattern, $controllerContent, $match)) {
            return [null, null];
        }

        $params = $match[1];

        // Cari FormRequest type hint (misal: StoreUserRequest $request)
        if (!preg_match('/(?:^|,\s*)([A-Z]\w*Request)\s+\$\w+/', $params, $reqMatch)) {
            return [null, null];
        }

        $requestShortName = $reqMatch[1];
        if (in_array($requestShortName, ['Request', 'FormRequest'], true)) {
            return [null, null];
        }

        // Resolve file FormRequest
        $requestFile = null;
        if (preg_match('/use\s+([^;]+?\\\\' . preg_quote($requestShortName, '/') . ');/', $controllerContent, $useMatch)) {
            $fqcn = trim($useMatch[1]);
            $relPath = str_replace(['App\\', '\\'], ['', '/'], $fqcn) . '.php';
            $candidate = $basePath . '/app/' . $relPath;
            if (file_exists($candidate)) {
                $requestFile = $candidate;
            }
        }

        if ($requestFile === null) {
            $candidate = $basePath . '/app/Http/Requests/' . $requestShortName . '.php';
            if (file_exists($candidate)) {
                $requestFile = $candidate;
            }
        }

        if ($requestFile === null) {
            return [$requestShortName, null];
        }

        // Analisis authorize() dari file
        $reqContent = @file_get_contents($requestFile);
        if ($reqContent === false) {
            return [$requestShortName, null];
        }

        $isAuthorized = $this->analyzeFormRequestAuthorizeStatic($reqContent);

        return [$requestShortName, $isAuthorized];
    }

    /**
     * Analisis method authorize() pada FormRequest class via Reflection.
     */
    private function analyzeFormRequestAuthorize(string $formRequestClass): ?bool
    {
        try {
            $refClass = new \ReflectionClass($formRequestClass);
            if (!$refClass->hasMethod('authorize')) {
                return null; // Tidak ada override authorize()
            }

            $authMethod = $refClass->getMethod('authorize');

            // Jika method tidak di-override (masih milik base class)
            if ($authMethod->getDeclaringClass()->getName() === 'Illuminate\Foundation\Http\FormRequest') {
                return null;
            }

            $fileName = $authMethod->getFileName();
            if (!$fileName || !file_exists($fileName)) {
                return null;
            }

            $startLine = $authMethod->getStartLine();
            $endLine = $authMethod->getEndLine();
            if (!$startLine || !$endLine) {
                return null;
            }

            $lines = file($fileName, FILE_IGNORE_NEW_LINES);
            if ($lines === false) {
                return null;
            }

            $body = implode("\n", array_slice($lines, $startLine - 1, $endLine - $startLine + 1));

            // Cek apakah ada logika otorisasi
            if (LaravelSecurityDictionary::hasAuthorizationCheck($body)) {
                return true;
            }

            $stripped = preg_replace('/\s+/', '', strtolower($body));

            if (str_contains($stripped, 'returnfalse;')) {
                return true; // Menolak akses secara default
            }

            if (str_contains($stripped, 'returntrue;')) {
                return false; // Return true tanpa logika = tidak terproteksi
            }

            return null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Analisis method authorize() dari konten file FormRequest (static parsing).
     */
    private function analyzeFormRequestAuthorizeStatic(string $content): ?bool
    {
        if (!preg_match('/public\s+function\s+authorize\s*\([^)]*\)/', $content, $match, PREG_OFFSET_CAPTURE)) {
            return null;
        }

        $offset = (int) $match[0][1];
        $body = $this->extractMethodBody($content, $offset);
        if ($body === null) {
            return null;
        }

        if (LaravelSecurityDictionary::hasAuthorizationCheck($body)) {
            return true;
        }

        $stripped = preg_replace('/\s+/', '', strtolower($body));

        if (str_contains($stripped, 'returnfalse;')) {
            return true;
        }

        if (str_contains($stripped, 'returntrue;')) {
            return false;
        }

        return null;
    }

    // =========================================================================
    // Static Parsing Helpers
    // =========================================================================

    /**
     * Extract middleware dari route statement dan enclosing group.
     *
     * @return string[]
     */
    private function extractStaticMiddleware(string $routeStatement, string $fullContent, int $offset): array
    {
        $middlewares = [];

        // Middleware pada route definition: ->middleware('auth', 'throttle:6,1') atau ->middleware(['auth'])
        if (preg_match_all('/->middleware\s*\(\s*(?:\[([^\]]*)\]|([^)]+))\s*\)/', $routeStatement, $mwMatches)) {
            foreach ($mwMatches[0] as $j => $mwMatch) {
                $mwBody = $mwMatches[1][$j] !== '' ? $mwMatches[1][$j] : $mwMatches[2][$j];
                if (preg_match_all('/[\'"]([^\'"]+)[\'"]/', $mwBody, $names)) {
                    $middlewares = array_merge($middlewares, $names[1]);
                }
            }
        }

        // Enclosing group middleware
        $middlewares = array_merge($middlewares, $this->getEnclosingGroupMiddleware($fullContent, $offset));

        return array_values(array_unique($middlewares));
    }

    /**
     * Dapatkan middleware dari enclosing Route::middleware()->group() atau Route::group(['middleware' => ...])
     *
     * @return string[]
     */
    private function getEnclosingGroupMiddleware(string $content, int $offset): array
    {
        $middlewares = [];
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
                    // Temukan statement pembuka grup
                    $stmtStart = max(0, (int) strrpos(substr($content, 0, $i), ';'));
                    if ($stmtStart === 0) {
                        $stmtStart = max(0, (int) strrpos(substr($content, 0, $i), '<?php'));
                    }
                    $stmt = substr($content, $stmtStart, $i - $stmtStart);

                    // Extract middleware dari statement group
                    if (preg_match_all('/[\'"]([^\'"]+)[\'"]/', $stmt, $names)) {
                        foreach ($names[1] as $name) {
                            if (preg_match('/^(auth|web|api|throttle|role|can|permission|admin|sanctum|verified)/i', $name)) {
                                $middlewares[] = $name;
                            }
                        }
                    }
                }
            }
            $i--;
        }

        return $middlewares;
    }

    /**
     * Extract controller dan action method dari route definition.
     *
     * @return array{0: string|null, 1: string|null}
     */
    private function extractControllerAction(string $routeStatement, string $fileContent, string $basePath): array
    {
        // Pattern: [UserController::class, 'store']
        if (preg_match('/\[\s*([A-Za-z0-9_\\\\]+)::class\s*,\s*[\'\"](\w+)[\'\"]\s*\]/', $routeStatement, $match)) {
            $controllerRef = $match[1];
            $method = $match[2];

            // Resolve FQCN via use statement
            $fqcn = $this->resolveClassFromUseStatements($controllerRef, $fileContent);

            return [$fqcn ?? $controllerRef, $method];
        }

        // Pattern: 'UserController@store'
        if (preg_match('/[\'\"]([A-Za-z0-9_\\\\]+)@(\w+)[\'\"]\s*[\)\]]/', $routeStatement, $match)) {
            return [$match[1], $match[2]];
        }

        // Pattern: UserController::class (invokable)
        if (preg_match('/,\s*([A-Za-z0-9_\\\\]+)::class\s*[\)]/', $routeStatement, $match)) {
            $fqcn = $this->resolveClassFromUseStatements($match[1], $fileContent);

            return [$fqcn ?? $match[1], '__invoke'];
        }

        return [null, null];
    }

    /**
     * Resolve FQCN dari short class name via 'use' statements.
     */
    private function resolveClassFromUseStatements(string $shortName, string $content): ?string
    {
        $pattern = '/use\s+([^;]+\\\\' . preg_quote($shortName, '/') . ')\s*;/';
        if (preg_match($pattern, $content, $match)) {
            return trim($match[1]);
        }

        return null;
    }

    /**
     * Extract route name dari ->name('route.name').
     */
    private function extractRouteName(string $routeStatement): ?string
    {
        if (preg_match('/->name\s*\(\s*[\'\"]([^\'\"]+)[\'\"]\s*\)/', $routeStatement, $match)) {
            return $match[1];
        }

        return null;
    }

    /**
     * Extract HTTP methods dari Route::match(['GET', 'POST'], ...).
     *
     * @return string[]
     */
    private function extractMatchMethods(string $content, int $offset): array
    {
        // Cari pattern: Route::match(['GET', 'POST'], ...)
        $excerpt = substr($content, $offset, 200);
        if (preg_match('/Route::match\s*\(\s*\[([^\]]+)\]/', $excerpt, $match)) {
            if (preg_match_all('/[\'\"](\w+)[\'"]/', $match[1], $methods)) {
                return array_map('strtoupper', $methods[1]);
            }
        }

        return ['GET'];
    }

    /**
     * Extract route statement lengkap dari offset hingga titik koma.
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
     * Extract method body dari opening brace ke closing brace.
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
     * Resolve file path controller dari class name.
     */
    private function resolveControllerFile(string $controller, string $basePath): ?string
    {
        // Coba konversi namespace ke path: App\Http\Controllers\UserController -> app/Http/Controllers/UserController.php
        $relPath = str_replace(['App\\', '\\'], ['', '/'], $controller) . '.php';
        $candidate = $basePath . '/app/' . $relPath;
        if (file_exists($candidate)) {
            return $candidate;
        }

        return null;
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
                    if (!in_array($f, $files, true)) {
                        $files[] = $f;
                    }
                }
            }
        }

        return $files;
    }

    /**
     * Dapatkan path relatif dari basePath.
     */
    private function getRelativePath(string $fullPath, string $basePath): string
    {
        $base = rtrim($basePath, '/') . '/';
        if (str_starts_with($fullPath, $base)) {
            return substr($fullPath, strlen($base));
        }

        return $fullPath;
    }

    /**
     * Reset cache konteks yang sudah di-resolve (memaksa re-resolve saat dipanggil lagi).
     */
    public function reset(): void
    {
        $this->resolvedContexts = [];
        $this->isResolved = false;
    }
}
