<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_events', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45)->index();
            $table->string('host', 255)->index();
            $table->string('method', 10)->default('GET');
            $table->text('raw_uri')->nullable();
            $table->text('normalized_uri')->nullable();
            $table->string('rule_id', 100)->nullable()->index();
            $table->string('category', 100)->nullable();
            $table->string('severity', 20)->default('low');
            $table->integer('score_delta')->default(0);
            $table->string('decision', 30)->default('ALLOW');
            $table->string('intended_decision', 30)->nullable();
            $table->text('user_agent')->nullable();
            $table->text('referer')->nullable();
            $table->string('request_id', 100)->nullable();
            $table->string('rule_version', 50)->nullable();
            $table->timestamp('created_at')->index();

            $table->index(['ip_address', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_events');
    }
};
