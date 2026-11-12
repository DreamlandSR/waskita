<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Golden;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Scanners\MassAssignmentScanner;

class MassAssignmentGoldenTest extends GoldenTestCase
{
    private MassAssignmentScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new MassAssignmentScanner();
    }

    public function test_flags_empty_guarded(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Models/User.php', <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $guarded = [];
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'MASS_ASSIGN_EMPTY_GUARDED', AuditResult::SEVERITY_CRITICAL);
    }

    public function test_passes_explicit_fillable(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Models/Product.php', <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    protected $fillable = ['name', 'price', 'description'];
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_sensitive_column_in_fillable(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Models/User.php', <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $fillable = ['name', 'email', 'password', 'role'];
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'MASS_ASSIGN_SENSITIVE_FILLABLE', AuditResult::SEVERITY_HIGH);
    }

    public function test_flags_request_all_in_create(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/PostController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function store()
    {
        Post::create($request->all());
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'MASS_ASSIGN_REQUEST_ALL', AuditResult::SEVERITY_HIGH);
    }

    public function test_passes_request_validated(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/PostController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function store(StorePostRequest $request)
    {
        Post::create($request->validated());
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_request_except_in_update(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/UserController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function update()
    {
        $user->update($request->except('_token'));
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'MASS_ASSIGN_REQUEST_EXCEPT', AuditResult::SEVERITY_HIGH);
    }
}
