<?php

declare(strict_types=1);

namespace Waskita\Security\Core;

/**
 * RouteContext - Value Object yang merepresentasikan konteks lengkap sebuah Rute Laravel.
 *
 * Menggabungkan informasi:
 * - Route (URI, HTTP methods, parameters, name)
 * - Middleware Stack (auth, throttle, role, can, dll)
 * - Controller & Action yang dituju
 * - FormRequest yang diinjeksi (jika ada)
 * - Status proteksi keamanan (isProtected, hasThrottle, hasCsrf, hasAuthorization)
 */
final class RouteContext
{
    /**
     * @param string $uri URI rute (misal: 'api/users/{user}')
     * @param string[] $methods HTTP methods (misal: ['GET', 'POST'])
     * @param string[] $middlewares Daftar middleware yang terpasang pada rute
     * @param string|null $controller Fully qualified controller class name atau null jika Closure
     * @param string|null $action Nama method controller yang dipanggil (misal: 'store', 'update')
     * @param string|null $name Nama rute (misal: 'users.show')
     * @param string[] $parameters Parameter URL dinamis (misal: ['user', 'id'])
     * @param string|null $formRequestClass Class FormRequest yang diinjeksi pada method controller
     * @param bool|null $formRequestAuthorized Status return FormRequest::authorize() jika terdeteksi
     * @param string|null $sourceFile File sumber pendefinisian rute atau controller
     * @param int|null $sourceLine Baris sumber pendefinisian rute atau controller
     */
    public function __construct(
        public readonly string $uri,
        public readonly array $methods,
        public readonly array $middlewares = [],
        public readonly ?string $controller = null,
        public readonly ?string $action = null,
        public readonly ?string $name = null,
        public readonly array $parameters = [],
        public readonly ?string $formRequestClass = null,
        public readonly ?bool $formRequestAuthorized = null,
        public readonly ?string $sourceFile = null,
        public readonly ?int $sourceLine = null,
    ) {}

    /**
     * Apakah rute ini dilindungi oleh middleware otentikasi (auth, auth:api, sanctum, dll).
     */
    public function isAuthenticated(): bool
    {
        foreach ($this->middlewares as $mw) {
            $lower = strtolower($mw);
            if (
                $lower === 'auth' ||
                str_starts_with($lower, 'auth:') ||
                str_contains($lower, 'sanctum') ||
                str_contains($lower, 'passport')
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Apakah rute ini dilindungi oleh rate limiting / throttle.
     */
    public function hasThrottle(): bool
    {
        foreach ($this->middlewares as $mw) {
            if (LaravelSecurityDictionary::hasRateLimiting($mw)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Dapatkan konfigurasi throttle jika ada (misal: 'throttle:60,1' -> '60,1').
     */
    public function getThrottleConfig(): ?string
    {
        foreach ($this->middlewares as $mw) {
            if (str_starts_with(strtolower($mw), 'throttle:')) {
                return substr($mw, strlen('throttle:'));
            }
        }

        return null;
    }

    /**
     * Apakah rute ini memiliki proteksi peran atau izin khusus (role, permission, admin).
     */
    public function hasRoleOrPermission(): bool
    {
        foreach ($this->middlewares as $mw) {
            $lower = strtolower($mw);
            if (
                str_starts_with($lower, 'role:') ||
                str_starts_with($lower, 'permission:') ||
                str_starts_with($lower, 'can:') ||
                in_array($lower, ['admin', 'role', 'permission'], true)
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Apakah rute ini menggunakan parameter model binding tanpa middleware 'can:'.
     */
    public function hasUnprotectedModelBinding(): bool
    {
        if (empty($this->parameters)) {
            return false;
        }

        // Filter slug atau kategori publik
        $nonPublicParams = array_filter(
            $this->parameters,
            static fn (string $p): bool => !in_array(strtolower($p), ['slug', 'kategori', 'category', 'year', 'month'], true)
        );

        if (empty($nonPublicParams)) {
            return false;
        }

        // Cek apakah ada middleware can:
        foreach ($this->middlewares as $mw) {
            if (str_starts_with(strtolower($mw), 'can:')) {
                return false;
            }
        }

        return !$this->hasRoleOrPermission();
    }

    /**
     * Apakah rute ditujukan ke controller admin (berdasarkan namespace atau nama).
     */
    public function isAdminRoute(): bool
    {
        if (str_starts_with(ltrim($this->uri, '/'), 'admin/')) {
            return true;
        }

        if ($this->controller !== null) {
            return str_contains($this->controller, '\\Admin\\') || str_contains($this->controller, 'AdminController');
        }

        return false;
    }

    /**
     * Cek apakah HTTP methods mengandung write method (POST, PUT, PATCH, DELETE).
     */
    public function isWriteAction(): bool
    {
        $writeMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
        $upperMethods = array_map('strtoupper', $this->methods);

        return !empty(array_intersect($upperMethods, $writeMethods));
    }

    /**
     * Gabungkan controller dan action menjadi identifier unik: 'App\Http\Controllers\UserController@show'.
     */
    public function getActionIdentifier(): ?string
    {
        if ($this->controller === null) {
            return null;
        }

        return $this->action !== null
            ? "{$this->controller}@{$this->action}"
            : $this->controller;
    }
}
