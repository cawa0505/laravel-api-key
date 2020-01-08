<?php

namespace Ejarnutowski\LaravelApiKey\Providers;

use Ejarnutowski\LaravelApiKey\Console\Commands\ActivateApiKey;
use Ejarnutowski\LaravelApiKey\Console\Commands\DeactivateApiKey;
use Ejarnutowski\LaravelApiKey\Console\Commands\DeleteApiKey;
use Ejarnutowski\LaravelApiKey\Console\Commands\GenerateApiKey;
use Ejarnutowski\LaravelApiKey\Console\Commands\ListApiKeys;
use Ejarnutowski\LaravelApiKey\Http\Middleware\AuthorizeApiKey;
use Ejarnutowski\LaravelApiKey\Models\ApiKey;
use Ejarnutowski\LaravelApiKey\Observers\ApiKeyObserver;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

class ApiKeyServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @param Router $router
     * @return void
     */
    public function boot(Router $router)
    {
        $this->registerMiddleware($router);
        $this->registerMigrations(__DIR__ . '/../../database/migrations');

        $this->publishes([
            __DIR__.'/../config/apikey.php' => config_path('apikey.php'),
        ], 'apikey-config');

        ApiKey::observe(ApiKeyObserver::class);
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register() {
        $this->commands([
            ActivateApiKey::class,
            DeactivateApiKey::class,
            DeleteApiKey::class,
            GenerateApiKey::class,
            ListApiKeys::class,
        ]);

        $this->mergeConfigFrom(
            __DIR__.'/../config/apikey.php', 'apikey'
        );
    }

    /**
     * Register middleware
     *
     * Support added for different Laravel versions
     *
     * @param Router $router
     */
    protected function registerMiddleware(Router $router)
    {
        $versionComparison = version_compare(app()->version(), '5.4.0');

        if ($versionComparison >= 0) {
            $router->aliasMiddleware('auth.apikey', AuthorizeApiKey::class);
        } else {
            $router->middleware('auth.apikey', AuthorizeApiKey::class);
        }
    }

    /**
     * Register migrations
     */
    protected function registerMigrations($migrationsDirectory)
    {
        $this->publishes([
            $migrationsDirectory => database_path('migrations')
        ], 'migrations');
    }
}
