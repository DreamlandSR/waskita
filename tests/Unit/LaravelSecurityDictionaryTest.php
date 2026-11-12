<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\LaravelSecurityDictionary;

class LaravelSecurityDictionaryTest extends TestCase
{
    public function test_contains_user_input(): void
    {
        $this->assertTrue(LaravelSecurityDictionary::containsUserInput('$request->input("name")'));
        $this->assertTrue(LaravelSecurityDictionary::containsUserInput('request()->get("id")'));
        $this->assertTrue(LaravelSecurityDictionary::containsUserInput('request("search")'));
        $this->assertTrue(LaravelSecurityDictionary::containsUserInput('$_GET["q"]'));
        $this->assertTrue(LaravelSecurityDictionary::containsUserInput('$_POST["comment"]'));
        $this->assertTrue(LaravelSecurityDictionary::containsUserInput('$input["email"]'));
        $this->assertTrue(LaravelSecurityDictionary::containsUserInput('Input::get("filter")'));

        $this->assertFalse(LaravelSecurityDictionary::containsUserInput('Icons::get("arrow")'));
        $this->assertFalse(LaravelSecurityDictionary::containsUserInput('$user->name'));
        $this->assertFalse(LaravelSecurityDictionary::containsUserInput('"static title"'));
    }

    public function test_is_sanitized(): void
    {
        $this->assertTrue(LaravelSecurityDictionary::isSanitized('Purifier::clean($input)'));
        $this->assertTrue(LaravelSecurityDictionary::isSanitized('clean($request->name)'));
        $this->assertTrue(LaravelSecurityDictionary::isSanitized('e($userInput)'));
        $this->assertTrue(LaravelSecurityDictionary::isSanitized('htmlspecialchars($data)'));
        $this->assertTrue(LaravelSecurityDictionary::isSanitized('new HtmlString("<p>safe</p>")'));
        $this->assertTrue(LaravelSecurityDictionary::isSanitized('new \Illuminate\Support\HtmlString("<p>safe</p>")'));
        $this->assertTrue(LaravelSecurityDictionary::isSanitized('$model->toHtml()'));
        $this->assertTrue(LaravelSecurityDictionary::isSanitized('number_format($price, 2)'));
        $this->assertTrue(LaravelSecurityDictionary::isSanitized('intval($id)'));

        $this->assertFalse(LaravelSecurityDictionary::isSanitized('$request->name'));
        $this->assertFalse(LaravelSecurityDictionary::isSanitized('$article->body'));
    }

    public function test_is_safe_view_helper(): void
    {
        $this->assertTrue(LaravelSecurityDictionary::isSafeViewHelper('Icons::get("cart")'));
        $this->assertTrue(LaravelSecurityDictionary::isSafeViewHelper('\App\Support\Icons::get("home")'));
        $this->assertTrue(LaravelSecurityDictionary::isSafeViewHelper('svg("heroicon-o-user")'));
        $this->assertTrue(LaravelSecurityDictionary::isSafeViewHelper('heroicon("bell")'));

        $customConfig = [
            'trusted_view_helpers' => ['AppHelper::renderBadge'],
        ];
        $this->assertTrue(LaravelSecurityDictionary::isSafeViewHelper('AppHelper::renderBadge("vip")', $customConfig));

        $this->assertFalse(LaravelSecurityDictionary::isSafeViewHelper('$user->bio'));
    }

    public function test_is_static_literal(): void
    {
        $this->assertTrue(LaravelSecurityDictionary::isStaticLiteral('"<b>Hello World</b>"'));
        $this->assertTrue(LaravelSecurityDictionary::isStaticLiteral("'Static HTML string'"));
        $this->assertTrue(LaravelSecurityDictionary::isStaticLiteral('Icons::get("check")'));

        $this->assertFalse(LaravelSecurityDictionary::isStaticLiteral('$request->name'));
        $this->assertFalse(LaravelSecurityDictionary::isStaticLiteral('$dynamicVar'));
        $this->assertFalse(LaravelSecurityDictionary::isStaticLiteral('Icons::get($dynamicIcon)'));
    }

    public function test_is_sensitive_column(): void
    {
        $this->assertTrue(LaravelSecurityDictionary::isSensitiveColumn('role'));
        $this->assertTrue(LaravelSecurityDictionary::isSensitiveColumn('is_admin'));
        $this->assertTrue(LaravelSecurityDictionary::isSensitiveColumn('password'));
        $this->assertTrue(LaravelSecurityDictionary::isSensitiveColumn('email_verified_at'));
        $this->assertTrue(LaravelSecurityDictionary::isSensitiveColumn('ROLE')); // case insensitive

        $customConfig = [
            'sensitive_columns' => ['is_verified_seller'],
        ];
        $this->assertTrue(LaravelSecurityDictionary::isSensitiveColumn('is_verified_seller', $customConfig));

        $this->assertFalse(LaravelSecurityDictionary::isSensitiveColumn('title'));
        $this->assertFalse(LaravelSecurityDictionary::isSensitiveColumn('name'));
    }

    public function test_match_sensitive_route(): void
    {
        $matchLogin = LaravelSecurityDictionary::matchSensitiveRoute('/login');
        $this->assertNotNull($matchLogin);
        $this->assertSame('login', $matchLogin['keyword']);

        $matchAdminLogin = LaravelSecurityDictionary::matchSensitiveRoute('admin/login');
        $this->assertNotNull($matchAdminLogin);

        $matchRegister = LaravelSecurityDictionary::matchSensitiveRoute('auth/register');
        $this->assertNotNull($matchRegister);

        $matchReset = LaravelSecurityDictionary::matchSensitiveRoute('password/reset');
        $this->assertNotNull($matchReset);

        $matchNonSensitive = LaravelSecurityDictionary::matchSensitiveRoute('/articles/view');
        $this->assertNull($matchNonSensitive);
    }

    public function test_has_rate_limiting(): void
    {
        $this->assertTrue(LaravelSecurityDictionary::hasRateLimiting("->middleware('throttle:6,1')"));
        $this->assertTrue(LaravelSecurityDictionary::hasRateLimiting("Route::middleware(['auth', 'throttle:login'])"));
        $this->assertTrue(LaravelSecurityDictionary::hasRateLimiting('RateLimiter::hit($key)'));
        $this->assertTrue(LaravelSecurityDictionary::hasRateLimiting('RateLimiter::for("login", fn () => ... )'));

        $this->assertFalse(LaravelSecurityDictionary::hasRateLimiting("->middleware('auth')"));
    }

    public function test_has_authorization_check(): void
    {
        $this->assertTrue(LaravelSecurityDictionary::hasAuthorizationCheck('$this->authorize("update", $post);'));
        $this->assertTrue(LaravelSecurityDictionary::hasAuthorizationCheck('Gate::allows("edit-settings")'));
        $this->assertTrue(LaravelSecurityDictionary::hasAuthorizationCheck('$request->user()->can("delete", $post)'));
        $this->assertTrue(LaravelSecurityDictionary::hasAuthorizationCheck('abort_unless(auth()->user()->isAdmin(), 403);'));

        $this->assertFalse(LaravelSecurityDictionary::hasAuthorizationCheck('$post = Post::find($id); return view("post", compact("post"));'));
    }

    public function test_is_allowed_by_strictness(): void
    {
        // Default: semua diizinkan
        $this->assertTrue(LaravelSecurityDictionary::isAllowedByStrictness(AuditResult::SEVERITY_INFO));

        // Pedantic: semua termasuk INFO
        $pedanticConfig = ['strictness_level' => 'pedantic'];
        $this->assertTrue(LaravelSecurityDictionary::isAllowedByStrictness(AuditResult::SEVERITY_INFO, $pedanticConfig));
        $this->assertTrue(LaravelSecurityDictionary::isAllowedByStrictness(AuditResult::SEVERITY_CRITICAL, $pedanticConfig));

        // Actionable: CRITICAL, HIGH, MEDIUM, LOW dibolehkan; INFO ditolak
        $actionableConfig = ['strictness_level' => 'actionable'];
        $this->assertTrue(LaravelSecurityDictionary::isAllowedByStrictness(AuditResult::SEVERITY_CRITICAL, $actionableConfig));
        $this->assertTrue(LaravelSecurityDictionary::isAllowedByStrictness(AuditResult::SEVERITY_HIGH, $actionableConfig));
        $this->assertTrue(LaravelSecurityDictionary::isAllowedByStrictness(AuditResult::SEVERITY_MEDIUM, $actionableConfig));
        $this->assertTrue(LaravelSecurityDictionary::isAllowedByStrictness(AuditResult::SEVERITY_LOW, $actionableConfig));
        $this->assertFalse(LaravelSecurityDictionary::isAllowedByStrictness(AuditResult::SEVERITY_INFO, $actionableConfig));

        // Minimal: hanya CRITICAL dan HIGH
        $minimalConfig = ['strictness_level' => 'minimal'];
        $this->assertTrue(LaravelSecurityDictionary::isAllowedByStrictness(AuditResult::SEVERITY_CRITICAL, $minimalConfig));
        $this->assertTrue(LaravelSecurityDictionary::isAllowedByStrictness(AuditResult::SEVERITY_HIGH, $minimalConfig));
        $this->assertFalse(LaravelSecurityDictionary::isAllowedByStrictness(AuditResult::SEVERITY_MEDIUM, $minimalConfig));
        $this->assertFalse(LaravelSecurityDictionary::isAllowedByStrictness(AuditResult::SEVERITY_LOW, $minimalConfig));
        $this->assertFalse(LaravelSecurityDictionary::isAllowedByStrictness(AuditResult::SEVERITY_INFO, $minimalConfig));
    }
}
