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

namespace PHPExperts\JWTGuardian\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use PHPExperts\JWTHelper\JWTHelper;
use Tymon\JWTAuth\Http\Middleware\Authenticate as JWTAuthenticate;

class AssignGuard extends JWTAuthenticate
{
    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param string  $guard
     *
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {
        if ($guard != null) {
            auth()->shouldUse($guard);
        }

        $request->attributes->set('authGuardKey', $guard);

        try {
            JWTHelper::authenticate();
        } catch (\Exception $e) {
            return new JsonResponse([
                'error' => $e->getMessage(),
            ], JsonResponse::HTTP_UNAUTHORIZED);
        }

        return $next($request);
    }
}
