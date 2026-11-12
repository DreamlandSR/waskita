<?php

declare(strict_types=1);

if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php';
}

// Prepend autoloader so that changes in waskita/src take precedence
spl_autoload_register(function (string $class) {
    if (str_starts_with($class, 'Waskita\\Security\\Tests\\')) {
        $relative = substr($class, strlen('Waskita\\Security\\Tests\\'));
        $file = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';
        if (file_exists($file)) {
            require_once $file;
            return true;
        }
    }
    if (str_starts_with($class, 'Waskita\\Security\\')) {
        $relative = substr($class, strlen('Waskita\\Security\\'));
        $file = dirname(__DIR__) . '/src/' . str_replace('\\', '/', $relative) . '.php';
        if (file_exists($file)) {
            require_once $file;
            return true;
        }
    }
    return false;
}, prepend: true);
