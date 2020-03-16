<?php declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| JWT Guardian Routes
|--------------------------------------------------------------------------
|
|
*/

use PHPExperts\JWTGuardian\Http\Controllers\Auth\PasswordAuthController;

Route::group(['prefix' => 'auth/members'], function () {
    Route::post('/register', [PasswordAuthController::class, 'register']);
    Route::post('/login', [PasswordAuthController::class, 'login']);
    Route::post('/logout', [PasswordAuthController::class, 'logout']);

    Route::get('/token', [PasswordAuthController::class, 'verifyResetToken']);
    Route::get('/token/{email}', [PasswordAuthController::class, 'requestResetToken']);

    Route::patch('/{memberId}/password', [PasswordAuthController::class, 'resetPassword']);

    Route::put('/{memberId}/password', [PasswordAuthController::class, 'updatePassword'])
        ->middleware('assign.guard:members');
});

Route::group(['prefix' => 'admin', 'middleware' => 'assign.guard:admins'], function () {
    // would begin with /admin/whatever
});
