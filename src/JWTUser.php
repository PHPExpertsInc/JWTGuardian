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

use Illuminate\Support\Facades\Hash;
use PHPExperts\ConciseUuid\ConciseUuidAuthModel;
use Tymon\JWTAuth\Contracts\JWTSubject;

/**
 * @property string $id
 * @property string $name
 * @property string $email
 * @property string $password
 **/
class JWTUser extends ConciseUuidAuthModel implements JWTSubject
{
    protected $table = 'users';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $guarded = [];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token',
    ];

    public function __construct(array $attributes = [])
    {
        $this->setTable(config('jwt-guardian.users_table'));

        parent::__construct($attributes);
    }

    public function setPasswordAttribute(string $password)
    {
        $this->attributes['password'] = Hash::make($password);
    }

    public function getJWTIdentifier(): string
    {
        return $this->id;
    }

    public function getJWTCustomClaims(): array
    {
        return [];
    }

    public function resetPassword(string $userKey, string $resetToken, string $password)
    {
        JWTResetToken::verify($userKey, $resetToken);
    }
}
