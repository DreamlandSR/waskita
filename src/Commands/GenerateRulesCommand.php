<?php

declare(strict_types=1);

namespace Waskita\Security\Commands;

use Illuminate\Console\Command;
use Symfony\Component\Yaml\Yaml;

/**
 * Generate starter YAML security rules customized for the host project.
 *
 * Scans models, controllers, and route files in the application to generate
 * project-tailored YAML security rules adhering to the Waskita rule schema.
 */
class GenerateRulesCommand extends Command
{
    /** @var string */
    protected $signature = 'waskita:generate-rules
        {--path=rules/security : Output directory for rules}';

    /** @var string */
    protected $description = 'Generate starter YAML security rules customized for this project';

    public function handle(): int
    {
        $relativePath = (string) $this->option('path');
        $outputDir    = base_path($relativePath);

        $this->newLine();
        $this->info("Scanning application structure to generate customized security rules...");

        if (! is_dir($outputDir)) {
            mkdir($outputDir, 0755, true);
            $this->line("Created directory: {$outputDir}");
        }

        // 1. Discover Models
        $models = $this->discoverModels();
        $this->line("Found " . count($models) . " Eloquent model(s).");

        // 2. Discover Controllers
        $controllers = $this->discoverControllers();
        $this->line("Found " . count($controllers) . " controller(s).");

        // 3. Discover Routes
        $routeFiles = $this->discoverRouteFiles();
        $this->line("Found " . count($routeFiles) . " route file(s).");

        // 4. Generate Rule Sets
        $generatedFiles = [];

        // Mass Assignment Rule for Models
        $massAssignmentRules = $this->generateMassAssignmentRules($models);
        $maPath = $outputDir . '/mass-assignment.yaml';
        file_put_contents($maPath, Yaml::dump($massAssignmentRules, 4, 2, Yaml::DUMP_MULTI_LINE_LITERAL_BLOCK));
        $generatedFiles[] = $maPath;

        // Route Protection Rules
        $routeRules = $this->generateRouteRules($routeFiles);
        $rrPath = $outputDir . '/route-protection.yaml';
        file_put_contents($rrPath, Yaml::dump($routeRules, 4, 2, Yaml::DUMP_MULTI_LINE_LITERAL_BLOCK));
        $generatedFiles[] = $rrPath;

        // Controller Authorization Rules
        $authRules = $this->generateControllerAuthRules($controllers);
        $caPath = $outputDir . '/controller-authorization.yaml';
        file_put_contents($caPath, Yaml::dump($authRules, 4, 2, Yaml::DUMP_MULTI_LINE_LITERAL_BLOCK));
        $generatedFiles[] = $caPath;

        $this->newLine();
        $this->info("Successfully generated security rule files in: {$outputDir}");
        foreach ($generatedFiles as $file) {
            $this->line("  ✔ " . basename($file));
        }
        $this->newLine();

        return self::SUCCESS;
    }

    /**
     * Discover Eloquent model class files in app/Models or app/.
     *
     * @return list<string> Class names
     */
    private function discoverModels(): array
    {
        $models = [];
        $paths  = [base_path('app/Models'), base_path('app')];

        foreach ($paths as $dir) {
            if (! is_dir($dir)) {
                continue;
            }

            $files = glob($dir . '/*.php') ?: [];
            foreach ($files as $file) {
                $content = (string) file_get_contents($file);
                if (str_contains($content, 'extends Model') || str_contains($content, 'extends Authenticatable')) {
                    $models[] = pathinfo($file, PATHINFO_FILENAME);
                }
            }
        }

        return array_unique($models);
    }

    /**
     * Discover Controllers in app/Http/Controllers.
     *
     * @return list<string> Controller names
     */
    private function discoverControllers(): array
    {
        $controllers = [];
        $dir = base_path('app/Http/Controllers');

        if (! is_dir($dir)) {
            return $controllers;
        }

        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir));
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $name = $file->getBasename('.php');
                if ($name !== 'Controller') {
                    $controllers[] = $name;
                }
            }
        }

        return $controllers;
    }

    /**
     * Discover route definition files in routes/.
     *
     * @return list<string> Relative route file paths
     */
    private function discoverRouteFiles(): array
    {
        $routes = [];
        $dir = base_path('routes');

        if (! is_dir($dir)) {
            return $routes;
        }

        $files = glob($dir . '/*.php') ?: [];
        foreach ($files as $file) {
            $routes[] = 'routes/' . basename($file);
        }

        return $routes;
    }

    /**
     * Generate custom Mass Assignment YAML rules.
     *
     * @param  list<string>  $models
     * @return array<string, mixed>
     */
    private function generateMassAssignmentRules(array $models): array
    {
        $sensitiveColumns = (array) config('waskita.sensitive_columns', [
            'role', 'is_admin', 'admin', 'password', 'remember_token', 'permissions',
        ]);

        $colsList = implode(', ', $sensitiveColumns);

        return [
            'id'          => 'project-custom-guarded-attributes',
            'name'        => 'Custom Sensitive Column Guarding',
            'description' => "Ensures models ({$colsList}) protect sensitive columns from mass assignment.",
            'severity'    => 'HIGH',
            'category'    => 'mass_assignment',
            'scanner'     => 'MassAssignmentScanner',
            'targets'     => [
                'include' => ['app/Models/**/*.php', 'app/*.php'],
            ],
            'checks'      => [
                'sensitive_columns' => $sensitiveColumns,
                'require_guarded_or_fillable' => true,
            ],
            'suggestion'  => 'Add sensitive columns to $guarded or ensure they are NOT in $fillable.',
            'tags'        => ['mass-assignment', 'models', 'owasp-a1'],
        ];
    }

    /**
     * Generate Route Protection YAML rules.
     *
     * @param  list<string>  $routeFiles
     * @return array<string, mixed>
     */
    private function generateRouteRules(array $routeFiles): array
    {
        $sensitiveRoutes = (array) config('waskita.sensitive_routes', [
            'login', 'masuk', 'password', 'lupa-kata-sandi', 'register', 'daftar',
        ]);

        return [
            'id'          => 'project-custom-route-throttle',
            'name'        => 'Authentication Rate Limiting Rules',
            'description' => 'Verifies that authentication routes have throttle middleware attached.',
            'severity'    => 'MEDIUM',
            'category'    => 'rate_limiting',
            'scanner'     => 'RateLimitScanner',
            'targets'     => [
                'include' => ! empty($routeFiles) ? $routeFiles : ['routes/web.php', 'routes/api.php'],
            ],
            'checks'      => [
                'endpoints'          => $sensitiveRoutes,
                'required_middleware' => ['throttle'],
            ],
            'suggestion'  => 'Apply throttle middleware: Route::middleware("throttle:login")->group(...)',
            'tags'        => ['routes', 'rate-limit', 'brute-force'],
        ];
    }

    /**
     * Generate Controller Authorization YAML rules.
     *
     * @param  list<string>  $controllers
     * @return array<string, mixed>
     */
    private function generateControllerAuthRules(array $controllers): array
    {
        return [
            'id'          => 'project-custom-controller-authorization',
            'name'        => 'Controller Authorization Check',
            'description' => 'Verifies that resourceful controller methods call authorizeResource or authorize.',
            'severity'    => 'HIGH',
            'category'    => 'authorization',
            'scanner'     => 'IdorScanner',
            'targets'     => [
                'include' => ['app/Http/Controllers/**/*.php'],
            ],
            'checks'      => [
                'methods'           => ['show', 'update', 'destroy', 'edit'],
                'require_authorize' => true,
            ],
            'suggestion'  => 'Add $this->authorizeResource(Model::class) in __construct or $this->authorize(...) in methods.',
            'tags'        => ['authorization', 'idor', 'controllers'],
        ];
    }
}
