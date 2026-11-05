<?php

declare(strict_types=1);

namespace Waskita\Security;

use Illuminate\Support\ServiceProvider;
use Waskita\Security\Commands\AuditCommand;
use Waskita\Security\Commands\FixCommand;
use Waskita\Security\Commands\GenerateRulesCommand;
use Waskita\Security\Commands\HeadersTestCommand;
use Waskita\Security\Core\AuditEngine;

/**
 * WaskitaServiceProvider - Service provider utama untuk package Waskita.
 *
 * - Mendaftarkan Artisan commands (waskita:audit, waskita:generate-rules, dll.)
 * - Merge konfigurasi config/waskita.php
 * - Publikasi config dan default rules
 */
class WaskitaServiceProvider extends ServiceProvider
{
    /**
     * Register bindings ke container.
     */
    public function register(): void
    {
        // Merge config waskita.php sehingga user bisa override sebagian
        $this->mergeConfigFrom(
            __DIR__ . '/../config/waskita.php',
            'waskita'
        );

        // Bind AuditEngine sebagai singleton
        $this->app->singleton(AuditEngine::class, function ($app) {
            /** @var array<string, mixed> $config */
            $config = $app['config']->get('waskita', []);

            return new AuditEngine($config);
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        // Publikasi config
        $this->publishes([
            __DIR__ . '/../config/waskita.php' => config_path('waskita.php'),
        ], 'waskita-config');

        // Publikasi default rules
        $this->publishes([
            __DIR__ . '/../rules/default' => base_path('waskita-rules'),
        ], 'waskita-rules');

        // Registrasi Artisan commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                AuditCommand::class,
                GenerateRulesCommand::class,
                HeadersTestCommand::class,
                FixCommand::class,
            ]);
        }
    }
}
