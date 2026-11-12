<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use Waskita\Security\Core\RouteContext;

/**
 * Unit tests untuk RouteContext Value Object.
 */
class RouteContextTest extends TestCase
{
    public function test_basic_construction_and_action_identifier(): void
    {
        $ctx = new RouteContext(
            uri: 'api/users/{user}',
            methods: ['GET'],
            middlewares: ['auth:sanctum'],
            controller: 'App\\Http\\Controllers\\UserController',
            action: 'show',
            name: 'users.show',
            parameters: ['user'],
        );

        $this->assertSame('api/users/{user}', $ctx->uri);
        $this->assertSame(['GET'], $ctx->methods);
        $this->assertSame('users.show', $ctx->name);
        $this->assertSame(['user'], $ctx->parameters);
        $this->assertSame('App\\Http\\Controllers\\UserController@show', $ctx->getActionIdentifier());
    }

    public function test_is_authenticated_detects_auth_middleware(): void
    {
        $authCtx = new RouteContext(uri: '/dashboard', methods: ['GET'], middlewares: ['auth']);
        $this->assertTrue($authCtx->isAuthenticated());

        $sanctumCtx = new RouteContext(uri: '/api/me', methods: ['GET'], middlewares: ['auth:sanctum', 'throttle:60,1']);
        $this->assertTrue($sanctumCtx->isAuthenticated());

        $passportCtx = new RouteContext(uri: '/api/me', methods: ['GET'], middlewares: ['passport']);
        $this->assertTrue($passportCtx->isAuthenticated());

        $publicCtx = new RouteContext(uri: '/', methods: ['GET'], middlewares: ['web']);
        $this->assertFalse($publicCtx->isAuthenticated());
    }

    public function test_has_throttle_detects_rate_limiting(): void
    {
        $throttled = new RouteContext(uri: '/login', methods: ['POST'], middlewares: ['throttle:5,1']);
        $this->assertTrue($throttled->hasThrottle());
        $this->assertSame('5,1', $throttled->getThrottleConfig());

        $noThrottle = new RouteContext(uri: '/register', methods: ['POST'], middlewares: ['web']);
        $this->assertFalse($noThrottle->hasThrottle());
        $this->assertNull($noThrottle->getThrottleConfig());
    }

    public function test_has_role_or_permission(): void
    {
        $adminCtx = new RouteContext(uri: '/admin/users', methods: ['GET'], middlewares: ['auth', 'role:admin']);
        $this->assertTrue($adminCtx->hasRoleOrPermission());

        $canCtx = new RouteContext(uri: '/posts/{post}/edit', methods: ['GET'], middlewares: ['auth', 'can:update,post']);
        $this->assertTrue($canCtx->hasRoleOrPermission());

        $plainCtx = new RouteContext(uri: '/profile', methods: ['GET'], middlewares: ['auth']);
        $this->assertFalse($plainCtx->hasRoleOrPermission());
    }

    public function test_has_unprotected_model_binding(): void
    {
        // Parameter {user} tanpa can: middleware
        $unprotected = new RouteContext(
            uri: '/users/{user}',
            methods: ['GET'],
            middlewares: ['auth'],
            parameters: ['user'],
        );
        $this->assertTrue($unprotected->hasUnprotectedModelBinding());

        // Parameter {user} dengan can: middleware -> terlindungi
        $protected = new RouteContext(
            uri: '/users/{user}',
            methods: ['GET'],
            middlewares: ['auth', 'can:view,user'],
            parameters: ['user'],
        );
        $this->assertFalse($protected->hasUnprotectedModelBinding());

        // Parameter {slug} dianggap publik -> tidak masalah
        $publicParam = new RouteContext(
            uri: '/articles/{slug}',
            methods: ['GET'],
            middlewares: [],
            parameters: ['slug'],
        );
        $this->assertFalse($publicParam->hasUnprotectedModelBinding());

        // Tanpa parameter -> tidak ada binding
        $noParam = new RouteContext(uri: '/dashboard', methods: ['GET'], middlewares: ['auth']);
        $this->assertFalse($noParam->hasUnprotectedModelBinding());
    }

    public function test_is_admin_route(): void
    {
        $adminUri = new RouteContext(uri: 'admin/settings', methods: ['GET']);
        $this->assertTrue($adminUri->isAdminRoute());

        $adminNs = new RouteContext(uri: '/api/users', methods: ['GET'], controller: 'App\\Http\\Controllers\\Admin\\UserController');
        $this->assertTrue($adminNs->isAdminRoute());

        $normalRoute = new RouteContext(uri: '/profile', methods: ['GET'], controller: 'App\\Http\\Controllers\\ProfileController');
        $this->assertFalse($normalRoute->isAdminRoute());
    }

    public function test_is_write_action(): void
    {
        $post = new RouteContext(uri: '/users', methods: ['POST']);
        $this->assertTrue($post->isWriteAction());

        $get = new RouteContext(uri: '/users', methods: ['GET', 'HEAD']);
        $this->assertFalse($get->isWriteAction());

        $multi = new RouteContext(uri: '/api/items', methods: ['GET', 'DELETE']);
        $this->assertTrue($multi->isWriteAction());
    }

    public function test_action_identifier_invokable(): void
    {
        $ctx = new RouteContext(uri: '/contact', methods: ['POST'], controller: 'App\\Http\\Controllers\\ContactController');
        $this->assertSame('App\\Http\\Controllers\\ContactController', $ctx->getActionIdentifier());
    }

    public function test_action_identifier_null_for_closure(): void
    {
        $ctx = new RouteContext(uri: '/health', methods: ['GET']);
        $this->assertNull($ctx->getActionIdentifier());
    }
}
