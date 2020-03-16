<?php declare(strict_types=1);

/**
 * This file is part of JWT Guardian, a PHP Experts, Inc., Project.
 *
 * Copyright © 2020 PHP Experts, Inc.
 * Author: Theodore R. Smith <theodore@phpexperts.pro>
 *   GPG Fingerprint: 4BF8 2613 1C34 87AC D28F  2AD8 EB24 A91D D612 5690
 *   https://www.phpexperts.pro/
 *   https://github.com/PHPExpertsInc/JWTGuardian
 *
 * This file is licensed under the MIT License.
 */

namespace PHPExperts\JWTGuardian\Http\Controllers\Auth;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use PHPExperts\JWTGuardian\Http\Controllers\BaseAuthController;
use Tymon\JWTAuth\JWT;

final class AuthSessionController extends BaseAuthController
{
    public function store(Request $request)
    {
        dd(config('jwt-guardian.user_key'));

        $authGuard = $this->grabAuthGuard($request);

        $credentials = $request->only([config('jwt-guardian.user_key'), 'password']);

        if (!$token = $authGuard->attempt($credentials)) {
            return new JsonResponse(['error' => 'Unauthorized'], 401);
        }

        // tymon/jwt-auth's JWT mixin is -not- friendly to static analyzers.
        // Thus, we need to inform them via the $authGuard that JWT is a valid mixin.
        /* @var JWT $authGuard */
        return $this->respondWithToken($token, $authGuard->factory()->getTTL());
    }

    public function destroy(Request $request)
    {
        $authGuard = $this->grabAuthGuard($request);
        $authGuard->logout();

        return new JsonResponse(['message' => 'Successfully logged out']);
    }
}
