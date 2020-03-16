<?php declare(strict_types=1);

namespace PHPExperts\JWTGuardian\Http\Controllers\Auth;

use App\Models\User;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\ValidationException;
use Illuminate\Foundation\Validation\ValidatesRequests;
use InvalidArgumentException;
use PHPExperts\JWTGuardian\Http\Controllers\BaseAuthController;
use PHPExperts\JWTGuardian\JWTUser;
use PHPExperts\JWTHelper\JWTHelper;
use RuntimeException;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\JWT;
use Tymon\JWTAuth\JWTGuard;

class PasswordAuthController extends BaseAuthController
{
    use ValidatesRequests;

    public function login(Request $request)
    {
//        $this->validatesWith([
//            'username' => ['required'],
//            'password' => ['required'],
//        ]);

        $payload = $request->only('username', 'password');
        $user = JWTUser::query()->where(['username' => $payload['username']])->first();

        if (!$user || !$token = JWTHelper::login($user))
        {
            return new JsonResponse([
                'error' => 'Invalid username or password',
            ], JsonResponse::HTTP_UNAUTHORIZED);
        }

        return new JsonResponse([
            'token' => $token,
            'user'  => $user,
        ]);
    }

    public function register(Request $request)
    {
        list($authGuardKey => $authGuard) = $this->grabAuthGuard($request);
        dd($authGuardKey, $authGuard);

        $userKey = config('jwt-guardian.user_key');
        $member = static::query()->create([
            $userKey   => $request->$userKey,
            'password' => $request->password,
        ]);

        $token = $this->authGuard->login($member);

        return $this->respondWithToken($token);
    }

    /**
     * Generates and emails a password reset token.
     *
     * @param Request $request
     * @return JsonResponse
     * @throws ValidationException
     */
    public function requestResetToken(Request $request): JsonResponse
    {
        $this->validate($request, [
            'email' => ['required', 'email'],
        ]);
        $email = $request->input('email');

        // 0. Ensure that the requested email is registered.
        /** @var Member|null $member */
        $member = Member::query()->where(['email' => strtolower($email)])->first();
        if (!$member) {
            // Due to very real security concerns, we always want to return this message.
            // This is so that hackers cannot determine what is a valid email or not, by
            // sending brute force requests.
            return response()->json([
                'message' => 'Reset token sent.',
            ], JsonResponse::HTTP_ACCEPTED);
        }

        // 1. Generate the Reset Token.
        $resetToken = MemberSecurity::generateResetToken($member->id);
        $resetURL = env('PLATFORM_URL') . "/reset-password/{$resetToken}";

        // 2. Send the email.
        Mail::to($email)->send(new PasswordResetEmail(
            $member->first_name,
            $resetURL
        ));

        return new JsonResponse([
            'message' => 'Reset token sent.',
        ], JsonResponse::HTTP_ACCEPTED);
    }

    /**
     * Verifies if a user token is valid or not.
     *
     * @param string $token
     * @return JsonResponse
     */
    public function verifyResetToken(string $token)
    {
        $payload = MemberSecurity::ensureValidToken($token);

        return new JsonResponse($payload);
    }

    /**
     * Updates a user's password if they provided a reset token.
     *
     * @param  Request             $request
     * @param  string              $zuoraId
     * @return JsonResponse
     * @throws ValidationException
     */
    public function resetPassword(Request $request, string $zuoraId): JsonResponse
    {
        if ($request->isMethod('PATCH')) {
            throw new RuntimeException('PATCH call has not been implemented');
        }

        try {
            /** @var Member $member */
            $member = Member::query()
                ->where(['zuora_id' => $zuoraId])->firstOrFail();
        } catch (ModelNotFoundException $e) {
            throw new InvalidArgumentException('Invalid member ID');
        }

        $this->validate($request, [
            'reset_token'           => 'required_with:password',
            'password'              => 'required|min:6|confirmed',
            'password_confirmation' => 'required|min:6',
        ]);

        // Make sure that the token is valid.
        $resetToken = $request->input('reset_token');

        $token = MemberSecurity::resetPassword($member->email, $resetToken, $request->input('password'));

        return $this->respondWithToken($token);
    }

    /**
     * Updates a user's password.
     *
     * @param  Request             $request
     * @param  string              $zuoraId
     * @return JsonResponse
     * @throws AuthenticationException
     * @throws ValidationException
     */
    public function changePassword(Request $request, string $zuoraId): JsonResponse
    {
        if ($request->isMethod('put')) {
            throw new RuntimeException('PUT call has not been implemented');
        }

        // Note: The user is *guaranteed* to be logged in due to the JWT Auth Guard.
        /** @var JWTUser|null $user */
        $user = Auth::user();

        if ($zuoraId !== $user->zuora_id) {
            throw new AuthenticationException(<<<MSG
                Your session has become corrupted (token/user mismatch).
                Please clear your cache and try again.
            MSG);
        }

        $this->validate($request, [
            'password'              => 'required|min:6|confirmed',
            'password_confirmation' => 'required|min:6',
        ]);

        $token = $user->password = $request->input('password');

        return $this->respondWithToken($token);
    }

    protected function respondWithToken(string $token, int $ttl = 300)
    {
        // tymon/jwt-auth's JWT mixin is -not- friendly to static analyzers.
        // Thus, we need to inform them via the $authGuard that JWT is a valid mixin.
        /** @var JWT $authGuard */
        $authGuard = $this->authGuard;

        return new JsonResponse([
            'access_token' => $token,
            'token_type'   => 'bearer',
            'expires_in'   => $authGuard->factory()->getTTL() ?? $ttl,
        ]);
    }
}
