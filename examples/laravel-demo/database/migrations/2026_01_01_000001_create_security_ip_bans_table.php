<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_ip_bans', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45)->index();
            $table->string('status', 20)->default('active');
            $table->string('reason', 255)->default('');
            $table->string('last_rule_id', 100)->nullable();
            $table->integer('risk_score')->default(0);
            $table->integer('violation_count')->default(0);
            $table->integer('offense_count')->default(0);
            $table->timestamp('banned_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamp('released_at')->nullable();
            $table->timestamp('challenge_passed_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['status', 'expires_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_ip_bans');
    }
};
