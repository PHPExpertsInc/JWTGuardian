<?php declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| JWT Guardian Routes
|--------------------------------------------------------------------------
|
|
*/

use App\Http\Controllers\Auth\PasswordAuthController;

/* @var \Illuminate\Routing\Router $router */
$router->group(['prefix' => 'auth/members'], function () use ($router) {
    $router->post('/register', [PasswordAuthController::class, 'register']);
    $router->post('/login', [PasswordAuthController::class, 'login']);
    $router->post('/logout', [PasswordAuthController::class, 'logout']);

    $router->get('/token', [PasswordAuthController::class, 'verifyResetToken']);
    $router->get('/token/{email}', [PasswordAuthController::class, 'requestResetToken']);

    $router->patch('/{memberId}/password', [PasswordAuthController::class, 'resetPassword']);

    $router->put('/{memberId}/password', [PasswordAuthController::class, 'updatePassword'])
        ->middleware('assign.guard:members');
});

$router->group(['prefix' => 'admin', 'middleware' => 'assign.guard:admins'], function () use ($router) {
    // would begin with /admin/whatever
});
