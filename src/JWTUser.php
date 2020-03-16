<?php declare(strict_types=1);

/**
 * This file is part of Covid Tracker, a Covid Research Project.
 *
 * Copyright © 2020 Theodore R. Smith <theodore@phpexperts.pro>
 *   GPG Fingerprint: 4BF8 2613 1C34 87AC D28F  2AD8 EB24 A91D D612 5690
 *   https://www.phpexperts.pro/
 *   https://github.com/PHPExpertsInc/Skeleton
 *
 * This file is licensed under the MIT License.
 */

namespace PHPExperts\JWTGuardian;

use Illuminate\Notifications\Notifiable;
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
    protected $fillable = [
        'username', 'name', 'email', 'password',
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token',
    ];

    public function setPasswordAttribute(string $password)
    {
        $this->attributes['password'] = Hash::make($password);
    }

    /**
     * Returns the loggedIn user if present, else seeded UnknownUser.
     *
     * @return User
     */
    public static function currentUser(): self
    {
        /** @var User $currentUser */
        $currentUser = Auth::user();

        if (!$currentUser) {
            $currentUser = self::query()->find(self::SYSTEM_USER_ID);
        }

        return $currentUser;
    }

    /**
     * @return string
     */
    public function getJWTIdentifier(): string
    {
        return $this->id;
    }

    /**
     * @return array
     */
    public function getJWTCustomClaims(): array
    {
        return [];
    }
}
