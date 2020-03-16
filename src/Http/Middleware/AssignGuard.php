<?php declare(strict_types=1);

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
     * @param  Request $request
     * @param  Closure $next
     * @param  string  $guard
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
