<?php declare(strict_types=1);

namespace PHPExperts\JWTGuardian;

use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use PHPExperts\JWTGuardian\Http\Middleware\AssignGuard;
use Tymon\JWTAuth\Providers\LaravelServiceProvider;

class JWTGuardianServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        // Load Tymon's JWTAuth Service Provider
        $jwtAuthSP = new LaravelServiceProvider($this->app);
        $jwtAuthSP->register();
    }
    /**
     * Boot the authentication services for the application.
     *
     * @return void
     */
    public function boot(Router $router)
    {
//        $this->app->configure('jwt-guardian');

        $path = realpath(__DIR__ . '/../config/jwt-guardian.php');
        $this->mergeConfigFrom($path, 'jwt-guardian');

        $this->app->mi([
            'assign.guard' => AssignGuard::class,
        ]);

        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'jwt-guardian');

        $this->app['auth']->extend('jwt-auth', function ($app, $name, array $config) {
            $guard = new JWTGuardian(
                $app['tymon.jwt'],
                $app['auth']->createUserProvider($config['provider']),
                $app['request']
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }
}
