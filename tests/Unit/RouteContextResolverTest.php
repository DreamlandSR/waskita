<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use Waskita\Security\Core\RouteContextResolver;

/**
 * Unit tests untuk RouteContextResolver.
 */
class RouteContextResolverTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tempDir = sys_get_temp_dir() . '/waskita_route_resolver_test_' . uniqid();
        mkdir($this->tempDir . '/routes', 0777, true);
        mkdir($this->tempDir . '/app/Http/Controllers', 0777, true);
        mkdir($this->tempDir . '/app/Http/Requests', 0777, true);
    }

    protected function tearDown(): void
    {
        $this->deleteDirectory($this->tempDir);
        parent::tearDown();
    }

    private function deleteDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $items = scandir($dir);
        if ($items === false) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            if (is_dir($path)) {
                $this->deleteDirectory($path);
            } else {
                @unlink($path);
            }
        }

        @rmdir($dir);
    }

    public function test_resolves_static_routes_with_methods_and_parameters(): void
    {
        $webRoutes = <<<'PHP'
<?php

use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/users/{id}', [UserController::class, 'show'])->name('users.show');
Route::post('/users', [UserController::class, 'store'])->middleware('auth');
Route::delete('/users/{id}', [UserController::class, 'destroy'])->middleware(['auth', 'role:admin']);
PHP;

        file_put_contents($this->tempDir . '/routes/web.php', $webRoutes);

        $resolver = RouteContextResolver::fromBasePath($this->tempDir);
        $contexts = $resolver->resolveAll($this->tempDir);

        $this->assertCount(4, $contexts);

        // Test root route
        $rootCtx = $resolver->findContextForUri('/');
        $this->assertNotNull($rootCtx);
        $this->assertSame(['GET'], $rootCtx->methods);
        $this->assertFalse($rootCtx->isAuthenticated());

        // Test show route
        $showCtx = $resolver->findContextForUri('/users/{id}');
        $this->assertNotNull($showCtx);
        $this->assertSame('users.show', $showCtx->name);
        $this->assertSame(['id'], $showCtx->parameters);
        $this->assertSame('App\\Http\\Controllers\\UserController@show', $showCtx->getActionIdentifier());

        // Test store route with auth
        $storeCtx = $resolver->findContextForAction('App\\Http\\Controllers\\UserController', 'store');
        $this->assertNotNull($storeCtx);
        $this->assertTrue($storeCtx->isAuthenticated());
        $this->assertFalse($storeCtx->hasRoleOrPermission());

        // Test delete route with role:admin
        $deleteCtx = $resolver->findContextForAction('App\\Http\\Controllers\\UserController', 'destroy');
        $this->assertNotNull($deleteCtx);
        $this->assertTrue($deleteCtx->hasRoleOrPermission());
    }

    public function test_resolves_sensitive_routes_without_throttle(): void
    {
        $routes = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

// Sensitif tanpa throttle -> harus tertangkap
Route::post('/login', [AuthController::class, 'login']);

// Sensitif dengan throttle -> harus diabaikan
Route::post('/register', [AuthController::class, 'register'])->middleware('throttle:5,1');

// Sensitif OTP GET -> harus tertangkap
Route::get('/otp/verify', [AuthController::class, 'verifyOtp']);
PHP;

        file_put_contents($this->tempDir . '/routes/web.php', $routes);

        $resolver = RouteContextResolver::fromBasePath($this->tempDir);
        $resolver->resolveAll($this->tempDir);

        $unprotectedSensitive = $resolver->getSensitiveRoutesWithoutThrottle();
        $this->assertCount(2, $unprotectedSensitive);

        $uris = array_map(static fn ($c) => $c->uri, $unprotectedSensitive);
        $this->assertContains('/login', $uris);
        $this->assertContains('/otp/verify', $uris);
        $this->assertNotContains('/register', $uris);
    }

    public function test_resolves_unprotected_model_binding_routes(): void
    {
        $routes = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

// Unprotected model binding
Route::get('/orders/{order}', [OrderController::class, 'show'])->middleware('auth');

// Protected by can: middleware
Route::get('/documents/{document}', [DocController::class, 'show'])->middleware(['auth', 'can:view,document']);

// Public slug (bukan model ID sensitif)
Route::get('/posts/{slug}', [PostController::class, 'show']);
PHP;

        file_put_contents($this->tempDir . '/routes/web.php', $routes);

        $resolver = RouteContextResolver::fromBasePath($this->tempDir);
        $resolver->resolveAll($this->tempDir);

        $unprotected = $resolver->getUnprotectedModelBindingRoutes();
        $this->assertCount(1, $unprotected);
        $this->assertSame('/orders/{order}', $unprotected[0]->uri);
    }

    public function test_resolves_form_request_in_controller(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\ProfileController;
use Illuminate\Support\Facades\Route;

Route::post('/profile', [ProfileController::class, 'update'])->middleware('auth');
PHP;

        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Http\Requests\UpdateProfileRequest;

class ProfileController
{
    public function update(UpdateProfileRequest $request)
    {
        return response()->json(['status' => 'ok']);
    }
}
PHP;

        $formRequest = <<<'PHP'
<?php

namespace App\Http\Requests;

class UpdateProfileRequest
{
    public function authorize(): bool
    {
        return auth()->check() && auth()->user()->can('update-profile');
    }
}
PHP;

        file_put_contents($this->tempDir . '/routes/web.php', $routes);
        file_put_contents($this->tempDir . '/app/Http/Controllers/ProfileController.php', $controller);
        file_put_contents($this->tempDir . '/app/Http/Requests/UpdateProfileRequest.php', $formRequest);

        $resolver = RouteContextResolver::fromBasePath($this->tempDir);
        $resolver->resolveAll($this->tempDir);

        $ctx = $resolver->findContextForAction('App\\Http\\Controllers\\ProfileController', 'update');
        $this->assertNotNull($ctx);
        $this->assertSame('UpdateProfileRequest', $ctx->formRequestClass);
        $this->assertTrue($ctx->formRequestAuthorized);
    }

    public function test_get_protected_and_public_routes(): void
    {
        $routes = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/', [HomeController::class, 'index']);
Route::get('/about', [HomeController::class, 'about']);
Route::get('/dashboard', [DashboardController::class, 'index'])->middleware('auth');
Route::get('/admin', [AdminController::class, 'index'])->middleware(['auth', 'role:admin']);
PHP;

        file_put_contents($this->tempDir . '/routes/web.php', $routes);

        $resolver = RouteContextResolver::fromBasePath($this->tempDir);
        $resolver->resolveAll($this->tempDir);

        $public = $resolver->getPublicRoutes();
        $protected = $resolver->getProtectedRoutes();

        $this->assertCount(2, $public);
        $this->assertCount(2, $protected);
    }
}
