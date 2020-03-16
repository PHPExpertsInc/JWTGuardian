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

use App\Models\User;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use PHPExperts\JWTGuardian\Exceptions\InvalidResetTokenException;
use PHPExperts\JWTGuardian\Http\Controllers\BaseAuthController;
use PHPExperts\JWTGuardian\JWTResetToken;
use PHPExperts\JWTGuardian\JWTUser;
use PHPExperts\JWTGuardian\Mail\PasswordResetEmail;
use PHPExperts\JWTHelper\JWTHelper;
use RuntimeException;
use Tymon\JWTAuth\JWT;

class PasswordAuthController extends BaseAuthController
{
    use ValidatesRequests;

    public function login(Request $request)
    {
        try {
            $this->validate($request, [
                'username' => ['required'],
                'password' => ['required'],
            ]);
        } catch (ValidationException $e) {
            return new JsonResponse([
                'error' => 'username and password are required.'
            ], JsonResponse::HTTP_BAD_REQUEST);
        }
        $payload = $request->only('username', 'password');
        $user = JWTUser::query()->where(['username' => $payload['username']])->first();

        $password = $user->password;
        $correctPassword = password_verify($payload['password'], $user->password);

        if (!$user || !$correctPassword || !$token = JWTHelper::login($user)) {
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
        dd([$authGuardKey, $authGuard]);

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
     * @throws ValidationException
     */
    public function requestResetToken(Request $request): JsonResponse
    {
        $this->validate($request, [
            'email' => ['required', 'email'],
        ]);
        $email = $request->input('email');

        // 0. Ensure that the requested email is registered.
        /** @var JWTUser|null $user */
        $user = (new JWTUser)->query()->where([config('jwt-auth.user_key') => strtolower($email)])->first();
        if (!$user) {
            // Due to very real security concerns, we always want to return this message.
            // This is so that hackers cannot determine what is a valid email or not, by
            // sending brute force requests.
            return response()->json([
                'message' => 'Reset token sent.',
            ], JsonResponse::HTTP_ACCEPTED);
        }

        // 1. Generate the Reset Token.
        $resetToken = JWTResetToken::generate($user->id);
        $resetURL = config('jwt-guardian.platform_url') . "/reset-password/{$resetToken}";

        // 2. Send the email.
        Mail::to($email)->send(new PasswordResetEmail(
            $user->first_name,
            $resetURL
        ));

        return new JsonResponse([
            'message' => 'Reset token sent.',
        ], JsonResponse::HTTP_ACCEPTED);
    }

    /**
     * Verifies if a user token is valid or not.
     *
     * @return JsonResponse
     */
    public function verifyResetToken(string $userKey, string $token)
    {
        try {
            JWTResetToken::verify($userKey, $resetToken);
        } catch (InvalidResetTokenException $e) {
            return new JsonResponse([
                'error' => 'Invalid password reset token.',
            ], JsonResponse::HTTP_UNAUTHORIZED);
        }

        return new JsonResponse([
            'verified' => true,
        ]);
    }

    /**
     * Updates a user's password if they provided a reset token.
     *
     * @throws ValidationException
     */
    public function resetPassword(Request $request, string $userKey): JsonResponse
    {
        if ($request->isMethod('PATCH')) {
            throw new RuntimeException('PATCH call has not been implemented');
        }

        try {
            /** @var JWTUser $member */
            $member = (new JWTUser)->query()
                ->where([config('jwt-auth.user_key') => $userKey])->firstOrFail();
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

        $token = JWTUser::resetPassword($userKey, $resetToken, $request->input('password'));

        return $this->respondWithToken($token);
    }

    /**
     * Updates a user's password.
     *
     * @param Request $request
     * @param string  $userKey
     * @return JsonResponse
     * @throws AuthenticationException
     * @throws ValidationException
     */
    public function changePassword(Request $request, string $userKey): JsonResponse
    {
        if ($request->isMethod('put')) {
            throw new RuntimeException('PUT call has not been implemented');
        }

        // Note: The user is *guaranteed* to be logged in due to the JWT Auth Guard.
        /** @var JWTUser|null $user */
        $user = Auth::user();
        $userKey = config('jwt-guardian.user_key');

        if ($userKey !== $user->$userKey) {
            throw new AuthenticationException(
                'Your session has become corrupted (token/user mismatch). ' .
                'Please clear your cache and try again.'
            );
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
        [$authGuardKey => $authGuard] = $this->grabAuthGuard($request);

        return new JsonResponse([
            'access_token' => $token,
            'token_type'   => 'bearer',
            'expires_in'   => $authGuard->factory()->getTTL() ?? $ttl,
        ]);
    }
}
