<?php

declare(strict_types=1);

namespace Waskita\Security\Core;

use Illuminate\Container\Container;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;

/**
 * ContainerBootstrapper - Mengelola deteksi dan bootstrap container Laravel untuk mode introspeksi runtime.
 *
 * Menyediakan API bersih bagi scanner untuk mengakses layanan Laravel
 * tanpa menduplikasi logika deteksi container di setiap scanner.
 *
 * Mendukung 2 mode:
 * 1. Deteksi otomatis via detect() — mencoba Container::getInstance() lalu bootstrap/app.php
 * 2. Pembungkusan container yang sudah ada via fromContainer()
 *
 * Semua method dijamin aman: tidak pernah melempar exception ke pemanggil,
 * tidak menjalankan migrasi/seeder, dan tidak mengubah state aplikasi.
 */
final class ContainerBootstrapper
{
    /**
     * @param Container $container Instance container Laravel yang aktif
     */
    private function __construct(
        private readonly Container $container,
    ) {}

    /**
     * Deteksi dan bootstrap container Laravel dari base path project.
     *
     * Urutan deteksi:
     * 1. Cek apakah class Illuminate\Container\Container tersedia
     * 2. Coba Container::getInstance() (untuk saat berjalan di dalam artisan)
     * 3. Jika tidak tersedia, bootstrap dari basePath/bootstrap/app.php
     * 4. Validasi binding esensial (router, config, app)
     *
     * @param string $basePath Root directory project Laravel
     * @return static|null Instance bootstrapper, atau null jika deteksi gagal
     */
    public static function detect(string $basePath): ?self
    {
        try {
            if (!class_exists(Container::class)) {
                return null;
            }

            // 1. Coba Container::getInstance() terlebih dahulu (sudah berjalan di dalam artisan/app)
            $container = self::tryGetExistingInstance();

            if ($container !== null && self::hasEssentialBindings($container)) {
                return new self($container);
            }

            // 2. Coba bootstrap dari basePath/bootstrap/app.php
            $container = self::tryBootstrapFromFile($basePath);

            if ($container !== null && self::hasEssentialBindings($container)) {
                return new self($container);
            }

            return null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Bungkus container yang sudah ada menjadi ContainerBootstrapper.
     *
     * @param Container $container Instance container Laravel yang sudah berjalan
     * @return static
     */
    public static function fromContainer(Container $container): self
    {
        return new self($container);
    }

    /**
     * Apakah container dapat digunakan (memiliki binding esensial).
     *
     * @return bool
     */
    public function isAvailable(): bool
    {
        try {
            return self::hasEssentialBindings($this->container);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Dapatkan instance container Laravel.
     *
     * @return Container
     */
    public function getContainer(): Container
    {
        return $this->container;
    }

    /**
     * Dapatkan instance Router jika tersedia.
     *
     * @return Router|null
     */
    public function getRouter(): ?Router
    {
        try {
            if (!$this->container->bound('router')) {
                return null;
            }

            $router = $this->container->make('router');

            return $router instanceof Router ? $router : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Ambil nilai konfigurasi dari container.
     *
     * @param string $key Kunci konfigurasi (misal: 'app.debug', 'session.driver')
     * @param mixed $default Nilai default jika kunci tidak ditemukan
     * @return mixed
     */
    public function getConfig(string $key, mixed $default = null): mixed
    {
        try {
            if (!$this->container->bound('config')) {
                return $default;
            }

            /** @var \Illuminate\Config\Repository $config */
            $config = $this->container->make('config');

            return $config->get($key, $default);
        } catch (\Throwable) {
            return $default;
        }
    }

    /**
     * Dapatkan koleksi rute sebagai array informasi rute.
     *
     * @return array<int, array{uri: string, methods: string[], middlewares: string[], controller: string|null, action: string|null, name: string|null, parameters: string[]}>
     */
    public function getRoutes(): array
    {
        try {
            $router = $this->getRouter();

            if ($router === null) {
                return [];
            }

            return $this->buildRouteInfoArray($router);
        } catch (\Throwable) {
            return [];
        }
    }

    /**
     * Dapatkan definisi middleware group.
     *
     * @return array<string, array<int, string>>
     */
    public function getMiddlewareGroups(): array
    {
        try {
            $router = $this->getRouter();

            if ($router === null) {
                return [];
            }

            /** @var array<string, array<int, string>> $groups */
            $groups = $router->getMiddlewareGroups();

            return $groups;
        } catch (\Throwable) {
            return [];
        }
    }

    /**
     * Dapatkan daftar middleware terdaftar (alias middleware).
     *
     * @return array<string, string>
     */
    public function getRegisteredMiddleware(): array
    {
        try {
            $router = $this->getRouter();

            if ($router === null) {
                return [];
            }

            /** @var array<string, string> $middleware */
            $middleware = $router->getMiddleware();

            return $middleware;
        } catch (\Throwable) {
            return [];
        }
    }

    // ─── Route Introspection ─────────────────────────────────────────

    /**
     * Dapatkan informasi detail untuk setiap rute yang terdaftar.
     *
     * @return array<int, array{uri: string, methods: string[], middlewares: string[], controller: string|null, action: string|null, name: string|null, parameters: string[]}>
     */
    public function getRouteInfo(): array
    {
        return $this->getRoutes();
    }

    /**
     * Dapatkan middleware stack untuk rute dengan URI tertentu.
     *
     * @param string $uri URI rute (misal: 'api/users/{user}')
     * @return string[]
     */
    public function getRouteMiddleware(string $uri): array
    {
        try {
            $router = $this->getRouter();

            if ($router === null) {
                return [];
            }

            $normalizedUri = ltrim($uri, '/');

            foreach ($router->getRoutes() as $route) {
                /** @var Route $route */
                if (ltrim($route->uri(), '/') === $normalizedUri) {
                    return $this->gatherMiddleware($route);
                }
            }

            return [];
        } catch (\Throwable) {
            return [];
        }
    }

    /**
     * Dapatkan class controller untuk rute dengan URI tertentu.
     *
     * @param string $uri URI rute (misal: 'api/users/{user}')
     * @return string|null Fully qualified class name controller, atau null jika tidak ditemukan
     */
    public function getControllerForRoute(string $uri): ?string
    {
        try {
            $router = $this->getRouter();

            if ($router === null) {
                return null;
            }

            $normalizedUri = ltrim($uri, '/');

            foreach ($router->getRoutes() as $route) {
                /** @var Route $route */
                if (ltrim($route->uri(), '/') === $normalizedUri) {
                    $action = $route->getActionName();

                    if ($action === null || $action === 'Closure') {
                        return null;
                    }

                    // Format: App\Http\Controllers\UserController@show
                    if (str_contains($action, '@')) {
                        return explode('@', $action)[0];
                    }

                    // Invokable controller: App\Http\Controllers\UserController
                    return $action;
                }
            }

            return null;
        } catch (\Throwable) {
            return null;
        }
    }

    // ─── Model Introspection ─────────────────────────────────────────

    /**
     * Dapatkan properti $fillable dari sebuah model Eloquent.
     *
     * @param string $modelClass Fully qualified class name model (misal: 'App\Models\User')
     * @return string[]|null Array nama kolom fillable, atau null jika model tidak ditemukan
     */
    public function getModelFillable(string $modelClass): ?array
    {
        try {
            if (!class_exists($modelClass)) {
                return null;
            }

            if (!is_subclass_of($modelClass, 'Illuminate\Database\Eloquent\Model')) {
                return null;
            }

            $instance = new $modelClass();

            /** @var string[] $fillable */
            $fillable = $instance->getFillable();

            return $fillable;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Dapatkan properti $guarded dari sebuah model Eloquent.
     *
     * @param string $modelClass Fully qualified class name model (misal: 'App\Models\User')
     * @return string[]|null Array nama kolom guarded, atau null jika model tidak ditemukan
     */
    public function getModelGuarded(string $modelClass): ?array
    {
        try {
            if (!class_exists($modelClass)) {
                return null;
            }

            if (!is_subclass_of($modelClass, 'Illuminate\Database\Eloquent\Model')) {
                return null;
            }

            $instance = new $modelClass();

            /** @var string[] $guarded */
            $guarded = $instance->getGuarded();

            return $guarded;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Dapatkan relasi yang didefinisikan pada model Eloquent.
     *
     * Mendeteksi method yang mengembalikan instance relasi Eloquent
     * (hasOne, hasMany, belongsTo, belongsToMany, morphTo, dll.)
     * melalui Reflection.
     *
     * @param string $modelClass Fully qualified class name model
     * @return array<int, array{name: string, type: string|null}> Daftar relasi [{name, type}]
     */
    public function getModelRelations(string $modelClass): array
    {
        try {
            if (!class_exists($modelClass)) {
                return [];
            }

            if (!is_subclass_of($modelClass, 'Illuminate\Database\Eloquent\Model')) {
                return [];
            }

            $relations = [];
            $refClass = new \ReflectionClass($modelClass);

            // Tipe relasi Eloquent yang dikenali
            $relationTypes = [
                'hasOne', 'hasMany', 'belongsTo', 'belongsToMany',
                'morphTo', 'morphOne', 'morphMany', 'morphToMany', 'morphedByMany',
                'hasManyThrough', 'hasOneThrough',
            ];
            $relationPattern = '/\$this\s*->\s*(' . implode('|', $relationTypes) . ')\s*\(/';

            foreach ($refClass->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
                // Abaikan method bawaan framework atau method statis
                if ($method->isStatic()) {
                    continue;
                }

                // Hanya periksa method yang didefinisikan di class model itu sendiri
                if ($method->getDeclaringClass()->getName() !== $modelClass) {
                    continue;
                }

                // Abaikan method dengan parameter wajib
                if ($method->getNumberOfRequiredParameters() > 0) {
                    continue;
                }

                // Baca source code method untuk deteksi pola relasi
                $fileName = $method->getFileName();
                if ($fileName === false || !file_exists($fileName)) {
                    continue;
                }

                $startLine = $method->getStartLine();
                $endLine = $method->getEndLine();

                if ($startLine === false || $endLine === false) {
                    continue;
                }

                $lines = file($fileName, FILE_IGNORE_NEW_LINES);

                if ($lines === false) {
                    continue;
                }

                $methodBody = implode("\n", array_slice($lines, $startLine - 1, $endLine - $startLine + 1));

                if (preg_match($relationPattern, $methodBody, $relMatch)) {
                    $relations[] = [
                        'name' => $method->getName(),
                        'type' => $relMatch[1],
                    ];
                }
            }

            return $relations;
        } catch (\Throwable) {
            return [];
        }
    }

    // ─── Private Helpers ─────────────────────────────────────────────

    /**
     * Coba ambil instance container yang sudah ada (dalam artisan/app context).
     */
    private static function tryGetExistingInstance(): ?Container
    {
        try {
            $instance = Container::getInstance();

            // Pastikan instance bukan container kosong
            if ($instance instanceof Container && $instance->bound('app')) {
                return $instance;
            }

            return null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Coba bootstrap aplikasi Laravel dari basePath/bootstrap/app.php.
     *
     * Set APP_ENV ke 'testing' untuk mencegah efek samping di produksi.
     * Menekan output error selama proses bootstrap.
     */
    private static function tryBootstrapFromFile(string $basePath): ?Container
    {
        $bootstrapFile = rtrim($basePath, '/') . '/bootstrap/app.php';

        if (!file_exists($bootstrapFile)) {
            return null;
        }

        // Simpan state sebelumnya
        $previousEnv = $_ENV['APP_ENV'] ?? null;
        $previousServerEnv = $_SERVER['APP_ENV'] ?? null;
        $previousErrorReporting = error_reporting();

        try {
            // Set environment ke testing untuk mencegah efek samping produksi
            $_ENV['APP_ENV'] = 'testing';
            $_SERVER['APP_ENV'] = 'testing';
            putenv('APP_ENV=testing');

            // Tekan output error selama bootstrap
            error_reporting(0);

            /** @var \Illuminate\Foundation\Application|Container|mixed $app */
            $app = @require $bootstrapFile;

            // Restore error reporting segera
            error_reporting($previousErrorReporting);

            if (!($app instanceof Container)) {
                return null;
            }

            // Jika ini Application (extends Container), boot kernel agar binding tersedia
            if (method_exists($app, 'make') && $app->bound('Illuminate\Contracts\Http\Kernel')) {
                /** @var \Illuminate\Contracts\Http\Kernel $kernel */
                $kernel = $app->make('Illuminate\Contracts\Http\Kernel');

                if (method_exists($kernel, 'bootstrap')) {
                    $kernel->bootstrap();
                }
            }

            return $app;
        } catch (\Throwable) {
            return null;
        } finally {
            // Restore environment state
            error_reporting($previousErrorReporting);

            if ($previousEnv !== null) {
                $_ENV['APP_ENV'] = $previousEnv;
                $_SERVER['APP_ENV'] = $previousServerEnv ?? $previousEnv;
                putenv("APP_ENV={$previousEnv}");
            } else {
                unset($_ENV['APP_ENV']);
                unset($_SERVER['APP_ENV']);
                putenv('APP_ENV');
            }
        }
    }

    /**
     * Validasi bahwa container memiliki binding esensial.
     */
    private static function hasEssentialBindings(Container $container): bool
    {
        try {
            return $container->bound('router')
                && $container->bound('config')
                && $container->bound('app');
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Kumpulkan middleware dari sebuah Route, dengan penanganan error.
     *
     * @return string[]
     */
    private function gatherMiddleware(Route $route): array
    {
        try {
            $middlewares = $route->gatherMiddleware();

            // Normalisasi: pastikan semua elemen adalah string
            return array_values(array_filter(
                $middlewares,
                static fn (mixed $mw): bool => is_string($mw),
            ));
        } catch (\Throwable) {
            return [];
        }
    }

    /**
     * Bangun array informasi rute dari seluruh route collection.
     *
     * @return array<int, array{uri: string, methods: string[], middlewares: string[], controller: string|null, action: string|null, name: string|null, parameters: string[]}>
     */
    private function buildRouteInfoArray(Router $router): array
    {
        $routeInfo = [];

        foreach ($router->getRoutes() as $route) {
            /** @var Route $route */
            $action = $route->getActionName();
            $controller = null;
            $actionMethod = null;

            if ($action !== null && $action !== 'Closure') {
                if (str_contains($action, '@')) {
                    [$controller, $actionMethod] = explode('@', $action, 2);
                } else {
                    // Invokable controller
                    $controller = $action;
                    $actionMethod = '__invoke';
                }
            }

            $routeInfo[] = [
                'uri' => $route->uri(),
                'methods' => $route->methods(),
                'middlewares' => $this->gatherMiddleware($route),
                'controller' => $controller,
                'action' => $actionMethod,
                'name' => $route->getName(),
                'parameters' => $route->parameterNames(),
            ];
        }

        return $routeInfo;
    }
}
