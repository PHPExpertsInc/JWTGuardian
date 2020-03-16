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

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class JWTGuardianMigration extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('jwt_reset_tokens', function (Blueprint $table) {
            $table->string('user_key')->primary();
            $table->char('token', 22);
            $table->timestamp('created_at', 0);

            $table->index('token');
        });

        $userTable = config('jwt-guardian.users_table');

        // Create the user table if it doesn't exist.
        if (!Schema::hasTable($userTable)) {
            Schema::create($userTable, function (Blueprint $table) {
                $table->char('id', 22)->primary();
                $table->string('username');
                $table->string('email');
                $table->string('password');
                $table->string('first_name');
                $table->string('last_name');
                $table->timestamps();

                $table->unique('username');
            });
        }

        if (!Schema::hasColumn($userTable, 'reset_token')) {
            Schema::table($userTable, function (Blueprint $table) {
                $table->char('reset_token', 22)->nullable();
            });
        }
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('jwt_reset_tokens');

        $userTable = config('jwt-guardian.users_table');
        Schema::table($userTable, function (Blueprint $table) {
            $table->dropColumn('reset_token');
        });
    }
}
