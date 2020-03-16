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

namespace PHPExperts\JWTGuardian\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use LogicException;
use Tymon\JWTAuth\JWTGuard;

abstract class BaseAuthController extends Controller
{
    /**
     * @return array[string => JWTGuard]
     */
    protected function grabAuthGuard(Request $request): array
    {
        if (!($authGuardKey = $request->get('authGuardKey'))) {
            throw new LogicException('This route must use the AuthGuard middleweare.');
        }

        try {
            /** @var JWTGuard $authGuard */
            $authGuard = auth($authGuardKey);
        } catch (\Throwable $e) {
            throw new LogicException("You need to edit config/jwt-guardian.php and add '$authGuardKey' as a guardian.");
        }

        return [$authGuardKey => $authGuard];
    }

    protected function respondWithToken(string $token, int $ttl = 300)
    {
        return new JsonResponse([
            'access_token' => $token,
            'token_type'   => 'bearer',
            'expires_in'   => $ttl,
        ]);
    }
}
