<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/home', fn () => response('home ok'))->name('home');

Route::get('/dashboard', fn () => response('dashboard ok'))->name('dashboard');

Route::get('/about', fn () => response('about ok'))->name('about');
