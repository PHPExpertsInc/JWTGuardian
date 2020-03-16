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

namespace Tests\Features;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use PHPExperts\ConciseUuid\ConciseUuid;
use PHPExperts\JWTGuardian\Tests\TestCase;
use PHPUnit\Framework\ExpectationFailedException;

class AuthenticationTest extends TestCase
{
    /** @var string */
    private $testUserId;

    /** @var array */
    private $userInfo;

    public function setUp(): void
    {
        parent::setUp();

        $this->testUserId = ConciseUuid::generateNewId();

        $this->userInfo = [
            'id'       => $this->testUserId,
            'username' => 'JWTGuardian',
            'password' => Hash::make('JWTGuardian4Eva!'),
        ];

        DB::table('users')
            ->insert($this->userInfo);
    }

    public function tearDown(): void
    {
        DB::table('users')
            ->delete($this->testUserId);

        parent::tearDown();
    }

    public function testCanLogin()
    {
        $response = $this->login($this->userInfo['username'], $this->userInfo['password']);
        $decoded = $response->decodeResponseJson();

        return $decoded['access_token'];
    }

    public function testCannotLogInWithBadCredentials()
    {
        $this->markTestIncomplete();

        $response = $this->post('/auth/users/login', [
            'username' => self::USERNAME,
            'password' => 'This is the wrong password!',
        ]);

        self::assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        $decoded = $response->decodeResponseJson();
        self::assertNotEmpty($decoded['error']);
        self::assertEquals('Unauthorized', $decoded['error']);
    }

    public function testCanUpdatePasswords()
    {
        $this->markTestIncomplete();

        $this->login(self::USERNAME, self::PASSWORD);
        $jwtToken = $this->token;

        $zuoraId = self::ZUORA_ID;
        // Use the native `json()` method, because `patch()` will include the X-API-Key,
        // which would invalidate this test.
        $newPassword = self::PASSWORD . '1';
        $response = $this->json('PATCH', "/auth/users/$zuoraId/password", [
            'password'              => $newPassword,
            'password_confirmation' => $newPassword,
        ], [
            'Authorization'         => "Bearer $jwtToken",
        ])->decodeResponseJson();

        self::assertArrayHasKey('access_token', $response);
        self::assertNotEmpty($response['access_token']);

        try {
            $this->login(self::USERNAME, self::PASSWORD);
            self::fail('Still logged in with the old password.');
        } catch (ExpectationFailedException $e) {
            self::assertTrue(true);
        }

        $this->login(self::USERNAME, $newPassword);
    }

    /** @testdox Cannot update another user's password */
    public function testCannotUpdateAnotherUsersPassword()
    {
        $this->markTestIncomplete();

        $this->login(self::USERNAME, self::PASSWORD);
        $jwtToken = $this->token;

        $zuoraId = self::ALT_ZUORA_ID;
        // Use the native `json()` method, because `patch()` will include the X-API-Key,
        // which would invalidate this test.
        $newPassword = self::PASSWORD . '1';
        $response = $this->json('PATCH', "/auth/users/$zuoraId/password", [
            'password'              => $newPassword,
            'password_confirmation' => $newPassword,
        ], [
            'Authorization'         => "Bearer $jwtToken",
        ]);

        self::assertEquals(JsonResponse::HTTP_BAD_REQUEST, $response->getStatusCode());
        $message = json_decode($response->getContent(), true)['message'];
        self::assertContains('Your session has become corrupted (token/user mismatch).', $message);
    }

    public function testThePasswordConfirmationMustMatch()
    {
        $this->markTestIncomplete();

        $this->login(self::USERNAME, self::PASSWORD);
        $jwtToken = $this->token;

        $zuoraId = self::ZUORA_ID;
        // Use the native `json()` method, because `patch()` will include the X-API-Key,
        // which would invalidate this test.
        $response = $this->json('PATCH', "/auth/users/$zuoraId/password", [
            'password'              => self::PASSWORD,
            'password_confirmation' => self::PASSWORD . 'doesnt match',
        ], [
            'Authorization'         => "Bearer $jwtToken",
        ])->decodeResponseJson();

        self::assertFalse($response['success']);
        self::assertEquals('The given data was invalid.', $response['message']);
        self::assertNotEmpty($response['errors']);
        self::assertNotEmpty($response['errors']['password']);
        self::assertEquals('The password confirmation does not match.', $response['errors']['password'][0]);
    }
}
