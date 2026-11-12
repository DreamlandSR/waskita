<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Golden;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Scanners\SqlInjectionScanner;

class SqlInjectionGoldenTest extends GoldenTestCase
{
    private SqlInjectionScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new SqlInjectionScanner();
    }

    public function test_flags_raw_query_with_concatenation(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/UserController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function search()
    {
        $name = request('name');
        $results = \DB::select("SELECT * FROM users WHERE name = '" . $name . "'");
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'SQLI_RAW_QUERY_CONCATENATION', AuditResult::SEVERITY_CRITICAL);
    }

    public function test_passes_parameterized_query(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/UserController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function search()
    {
        $results = \DB::select('SELECT * FROM users WHERE name = ?', [request('name')]);
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_whereraw_with_interpolation(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/OrderController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function filter()
    {
        $status = request('status');
        $orders = Order::whereRaw("status = '$status'")->get();
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'SQLI_RAW_QUERY_CONCATENATION', AuditResult::SEVERITY_CRITICAL);
    }

    public function test_passes_whereraw_with_binding(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/OrderController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function filter()
    {
        $orders = Order::whereRaw('status = ?', [request('status')])->get();
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_orderby_user_input_without_whitelist(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/ProductController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class ProductController
{
    public function index()
    {
        $products = Product::query()->orderBy($request->input('sort'))->get();
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'SQLI_ORDER_BY_USER_INPUT', AuditResult::SEVERITY_HIGH);
    }

    public function test_passes_orderby_with_whitelist(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/ProductController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class ProductController
{
    public function index()
    {
        $sort = in_array($request->input('sort'), ['name', 'price']) ? $request->input('sort') : 'id';
        $products = Product::orderBy($sort)->get();
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }
}
