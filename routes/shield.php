<?php

declare(strict_types=1);

use Ganadev\Shield\Laravel\Http\Controllers\AdminController;
use Ganadev\Shield\Laravel\Http\Controllers\ChallengeController;
use Illuminate\Support\Facades\Route;

Route::middleware('web')->group(function () {
    Route::get('/shield/challenge', [ChallengeController::class, 'show'])
        ->name('shield.challenge');

    Route::post('/shield/challenge/verify', [ChallengeController::class, 'verify'])
        ->name('shield.challenge.verify')
        ->middleware('throttle:10,1');
});

if (config('shield.admin.enabled', false)) {
    $prefix = (string) config('shield.admin.prefix', 'shield');
    $middleware = (array) config('shield.admin.middleware', ['web', 'auth']);

    Route::middleware($middleware)->prefix($prefix)->group(function () {
        Route::get('/bans', [AdminController::class, 'bans'])->name('shield.bans');
        Route::get('/bans/{id}', [AdminController::class, 'banDetail'])->name('shield.bans.detail');
        Route::post('/bans/{id}/release', [AdminController::class, 'release'])->name('shield.bans.release');
        Route::post('/bans/{id}/extend', [AdminController::class, 'extend'])->name('shield.bans.extend');
        Route::get('/events', [AdminController::class, 'events'])->name('shield.events');
        Route::get('/rules', [AdminController::class, 'rules'])->name('shield.rules');
        Route::get('/health', [AdminController::class, 'health'])->name('shield.health');
    });
}
