<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Tests;

use Ganadev\Shield\Laravel\Middleware\SecurityFirewallMiddleware;
use Ganadev\Shield\Laravel\ShieldServiceProvider;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Http\Kernel;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [ShieldServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        tap($app->make('config'), function (Repository $config) {
            $config->set('database.default', 'sqlite');
            $config->set('database.connections.sqlite', [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
            ]);
            $config->set('cache.default', 'array');
            $config->set('shield.mode', 'enforce');
            $config->set('shield.challenge.driver', 'null');
            // Record every decision so tests can assert on the event log
            // without opting in per case.
            $config->set('shield.logging.level', 'all');
            $config->set('app.key', 'base64:47v1LbFEGV5Tsf+IMtI66K/PVuyP/r9wGCE67OFTYZY=');
        });
    }

    protected function resolveApplicationHttpMiddlewares($app): void
    {
        parent::resolveApplicationHttpMiddlewares($app);

        $app->afterResolving(Kernel::class, function ($kernel) {
            $kernel->pushMiddleware(SecurityFirewallMiddleware::class);
        });
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }

    protected function defineRoutes($router): void
    {
        $router->get('/home', fn () => 'home')->name('home');
        $router->get('/dashboard', fn () => 'dashboard')->name('dashboard');
    }
}
