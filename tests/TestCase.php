<?php

declare(strict_types=1);

namespace Waskita\Security\Tests;

use Waskita\Security\WaskitaServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;

/**
 * Base test case for Waskita package.
 *
 * Uses Orchestra Testbench to boot a minimal Laravel application
 * with the package service provider loaded.
 */
abstract class TestCase extends BaseTestCase
{
    /**
     * Get the package providers to register.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return list<class-string<\Illuminate\Support\ServiceProvider>>
     */
    protected function getPackageProviders($app): array
    {
        return [
            WaskitaServiceProvider::class,
        ];
    }

    /**
     * Define environment setup.
     *
     * @param  \Illuminate\Foundation\Application  $app
     */
    protected function defineEnvironment($app): void
    {
        // Set default configuration for tests
        $app['config']->set('waskita.severity_threshold', 'low');
        $app['config']->set('waskita.fail_on', 'high');
        $app['config']->set('waskita.ignore_paths', ['vendor', 'node_modules']);
        $app['config']->set('waskita.sensitive_columns', [
            'role', 'is_admin', 'admin', 'password', 'remember_token', 'permissions',
        ]);
        $app['config']->set('waskita.sensitive_routes', [
            'login', 'masuk', 'password', 'lupa-kata-sandi', 'register', 'daftar',
        ]);
        $app['config']->set('waskita.required_headers', [
            'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy',
        ]);
    }
}
