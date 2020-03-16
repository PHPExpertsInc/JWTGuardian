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

namespace Tests\Feature\Members;

use Illuminate\Foundation\Testing\TestResponse;
use Illuminate\Http\Response;
use Tests\TestCase as BaseTestCase;

class TestCase extends BaseTestCase
{
    protected $token = '';

    public function login(string $username, string $password): TestResponse
    {
        $response = $this->json('POST', '/auth/members/login', [
            'username' => $username,
            'password' => $password,
        ]);

        $decoded = $response->decodeResponseJson();
        self::assertEquals(Response::HTTP_OK, $response->getStatusCode(), json_encode($decoded));

        $this->token = $decoded['access_token'];

        return $response;
    }

    /**
     * @param $uri
     *
     * @return TestResponse
     */
    public function get($uri, array $headers = [])
    {
        return parent::get($uri, $headers + [
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $this->token,
        ]);
    }

    /**
     * @param string $uri
     *
     * @return TestResponse
     */
    public function post($uri, array $payload = [], array $headers = [])
    {
        return parent::json('POST', $uri, $payload, $headers + [
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $this->token,
        ]);
    }

    /**
     * @param string $uri
     *
     * @return TestResponse
     */
    public function put($uri, array $payload = [], array $headers = [])
    {
        return parent::json('PUT', $uri, $payload, $headers + [
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $this->token,
        ]);
    }

    /**
     * @param string $uri
     *
     * @return TestResponse
     */
    public function patch($uri, array $payload = [], array $headers = [])
    {
        return parent::json('PATCH', $uri, $payload, $headers + [
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $this->token,
        ]);
    }

    /**
     * @param string $uri
     *
     * @return TestResponse
     */
    public function delete($uri, array $payload = [], array $headers = [])
    {
        return parent::json('DELETE', $uri, $payload, $headers + [
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $this->token,
        ]);
    }
}
