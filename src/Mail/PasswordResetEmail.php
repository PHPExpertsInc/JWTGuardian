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

namespace PHPExperts\JWTGuardian\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class PasswordResetEmail extends Mailable
{
    use Queueable;
    use SerializesModels;

    /** @var string */
    private $firstName;

    /** @var string */
    private $resetURL;

    public function __construct($firstName, $resetURL)
    {
        $this->firstName = $firstName;
        $this->resetURL = $resetURL;
    }

    public function build()
    {
        return $this->view('jwt-guardian:resetPasswordEmail', [
            'firstName' => $this->firstName,
            'resetURL'  => $this->resetURL,
        ]);
    }
}
