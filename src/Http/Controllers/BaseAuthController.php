<?php declare(strict_types=1);

namespace PHPExperts\JWTGuardian\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use LogicException;
use Tymon\JWTAuth\JWTGuard;

abstract class BaseAuthController extends Controller
{
    /**
     * @param Request $request
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
