<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel;

use Ganadev\Shield\Core\Challenge\ChallengeDriverInterface;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Engine\ShieldEngine;
use Ganadev\Shield\Core\Rules\RuleRepository;
use Ganadev\Shield\Laravel\Cache\LaravelCacheAdapter;
use Ganadev\Shield\Laravel\Console\Commands\ShieldHealthCommand;
use Ganadev\Shield\Laravel\Console\Commands\ShieldPruneCommand;
use Ganadev\Shield\Laravel\Console\Commands\ShieldReleaseCommand;
use Ganadev\Shield\Laravel\Console\Commands\ShieldReplayCommand;
use Ganadev\Shield\Laravel\Console\Commands\ShieldReportCommand;
use Ganadev\Shield\Laravel\Console\Commands\ShieldRulesListCommand;
use Ganadev\Shield\Laravel\Middleware\SecurityFirewallMiddleware;
use Ganadev\Shield\Laravel\Support\ShieldResolver;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Contracts\View\Factory;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

final class ShieldServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/shield.php', 'shield');

        $this->app->singleton(ShieldResolver::class, fn (Container $app) => new ShieldResolver($app));
        $this->app->singleton(ShieldConfig::class, fn (Container $app) => $app->make(ShieldResolver::class)->config());
        $this->app->singleton(RuleRepository::class, fn (Container $app) => $app->make(ShieldResolver::class)->rules());
        $this->app->singleton(ShieldEngine::class, fn (Container $app) => $app->make(ShieldResolver::class)->engine());
        $this->app->singleton(ChallengeDriverInterface::class, fn (Container $app) => $app->make(ShieldResolver::class)->challengeDriver());
        $this->app->singleton(LaravelCacheAdapter::class, fn (Container $app) => $app->make(ShieldResolver::class)->cacheAdapter());
        $this->app->singleton(SecurityFirewallMiddleware::class, fn (Container $app) => new SecurityFirewallMiddleware(
            $app->make(ShieldEngine::class),
            $app->make(ShieldConfig::class),
            $app->make(LaravelCacheAdapter::class),
            $app->make(UrlGenerator::class),
            $app->make(Factory::class),
        ));
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/shield.php' => config_path('shield.php'),
            ], 'shield-config');

            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'shield-migrations');
        }

        $this->loadRoutesFrom(__DIR__.'/../routes/shield.php');
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'shield');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../resources/views' => resource_path('views/vendor/shield'),
            ], 'shield-views');
        }

        $this->commands([
            ShieldReportCommand::class,
            ShieldPruneCommand::class,
            ShieldReleaseCommand::class,
            ShieldReplayCommand::class,
            ShieldRulesListCommand::class,
            ShieldHealthCommand::class,
        ]);

        $this->app->make(Router::class)
            ->aliasMiddleware('shield.firewall', SecurityFirewallMiddleware::class);
    }
}
