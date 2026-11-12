<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Unit;

use Illuminate\Container\Container;
use PHPUnit\Framework\TestCase;
use Waskita\Security\Core\ContainerBootstrapper;

class ContainerBootstrapperTest extends TestCase
{
    public function test_detect_returns_null_on_non_laravel_dir(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_dummy_' . uniqid();
        mkdir($tempDir);

        try {
            $bootstrapper = ContainerBootstrapper::detect($tempDir);
            // It should return null without throwing exception
            $this->assertNull($bootstrapper);
        } finally {
            rmdir($tempDir);
        }
    }

    public function test_from_container_wraps_container(): void
    {
        $container = new Container();
        $bootstrapper = ContainerBootstrapper::fromContainer($container);

        $this->assertInstanceOf(ContainerBootstrapper::class, $bootstrapper);
        $this->assertSame($container, $bootstrapper->getContainer());
        // Empty container does not have essential bindings (router, config, app)
        $this->assertFalse($bootstrapper->isAvailable());

        // When essential bindings are present
        $container->instance('router', new \stdClass());
        $container->instance('config', new \stdClass());
        $container->instance('app', $container);

        $this->assertTrue($bootstrapper->isAvailable());
    }

    public function test_get_config_with_default(): void
    {
        $container = new Container();
        $bootstrapper = ContainerBootstrapper::fromContainer($container);

        // When config service is not bound, getConfig returns default
        $this->assertSame('default_val', $bootstrapper->getConfig('app.name', 'default_val'));
    }

    public function test_get_routes_empty_when_no_router(): void
    {
        $container = new Container();
        $bootstrapper = ContainerBootstrapper::fromContainer($container);

        $this->assertSame([], $bootstrapper->getRoutes());
        $this->assertSame([], $bootstrapper->getRouteInfo());
    }
}
