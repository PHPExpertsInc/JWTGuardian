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

namespace PHPExperts\JWTGuardian;

use Carbon\Carbon;
use PHPExperts\ConciseUuid\ConciseUuid;
use PHPExperts\ConciseUuid\ConciseUuidModel;
use PHPExperts\JWTGuardian\Exceptions\InvalidResetTokenException;

/**
 * @property string $user_key
 * @property string $reset_token
 * @property Carbon $created_at
 **/
class JWTResetToken extends ConciseUuidModel
{
    protected $table = 'reset_tokens';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'reset_token',
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token',
    ];

    public static function generate(string $userKey): self
    {
        /** @var self $resetToken */
        $resetToken = self::query()->create([
            'user_key' => $userKey,
            'token'    => ConciseUuid::generateNewId(),
        ]);

        return $resetToken;
    }

    /**
     * @return static
     *
     * @throws InvalidResetTokenException
     */
    public static function verify(string $userKey, string $token): self
    {
        /** @var self $resetToken */
        $resetToken = self::query()
            ->where([
                'user_key' => $userKey,
                'token'    => $token,
            ])
            ->first();

        if (!$resetToken) {
            throw new InvalidResetTokenException();
        }

        return $resetToken;
    }
}
