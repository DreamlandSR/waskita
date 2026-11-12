<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Golden;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Scanners\RateLimitScanner;

class RateLimitGoldenTest extends GoldenTestCase
{
    private RateLimitScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new RateLimitScanner();
    }

    public function test_flags_login_without_throttle(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'routes/web.php', <<<'PHP'
<?php

Route::post('/login', 'AuthController@login');
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'RATE_LIMIT_SENSITIVE_ENDPOINT', AuditResult::SEVERITY_HIGH);
    }

    public function test_passes_login_with_throttle(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'routes/web.php', <<<'PHP'
<?php

Route::post('/login', 'AuthController@login')->middleware('throttle:6,1');
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_register_without_throttle(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'routes/web.php', <<<'PHP'
<?php

Route::post('/register', 'AuthController@register');
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'RATE_LIMIT_SENSITIVE_ENDPOINT', AuditResult::SEVERITY_HIGH);
    }

    public function test_passes_throttled_group(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'routes/web.php', <<<'PHP'
<?php

Route::middleware(['throttle:10,1'])->group(function () {
    Route::post('/login', 'AuthController@login');
    Route::post('/register', 'AuthController@register');
});
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_forgot_password_without_throttle(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'routes/web.php', <<<'PHP'
<?php

Route::post('/forgot-password', 'PasswordController@sendResetLink');
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'RATE_LIMIT_SENSITIVE_ENDPOINT', AuditResult::SEVERITY_HIGH);
    }

    public function test_passes_non_sensitive_route(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'routes/web.php', <<<'PHP'
<?php

Route::post('/articles', 'ArticleController@store');
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }
}
