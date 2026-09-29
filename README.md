# Ganadev Laravel Shield

**Adapter Laravel untuk Ganadev Shield** — adaptive application firewall yang menjadi lapisan pertahanan
terakhir di level aplikasi.

Package ini menyambungkan inti `ganadev/shield-core` ke Laravel: middleware firewall, penyimpanan database
(`security_events`, `security_ip_bans`), adapter cache, halaman challenge (Turnstile/reCAPTCHA/null), cookie
trusted, serta perintah CLI/Admin.

## Install

```bash
composer require ganadev/laravel-shield
```

`laravel-shield` otomatis menarik `ganadev/shield-core`.

## Setup singkat

```bash
php artisan vendor:publish --provider="Ganadev\Shield\Laravel\ShieldServiceProvider" --tag=shield-config
php artisan vendor:publish --provider="Ganadev\Shield\Laravel\ShieldServiceProvider" --tag=shield-migrations
php artisan migrate
```

Daftarkan middleware global di `bootstrap/app.php`:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->append([
        \Ganadev\Shield\Laravel\Middleware\SecurityFirewallMiddleware::class,
    ]);
})
```

Mulai dengan mode `observe` (default), lalu naikkan ke `enforce` setelah memantau `shield:report`.
Dokumentasi lengkap: `config/shield.php` berisi semua opsi beserta komentar.

## Fitur

- Blok probe file sensitif (`.env`, `.git`, AWS credentials, `wp-config.php`, ...) & path traversal / RCE.
- Verifikasi crawler (Googlebot/Bing/Yandex/dll) via reverse-DNS + CIDR — bot resmi lewat, bot palsu di-challenge.
- Inspeksi body + rule pack injection (SQLi/XSS/LFI/command) — body tidak pernah disimpan.
- Rate-limit path sensitif (brute-force login), behavior burst/404, skor risiko → challenge/ban.
- Halaman challenge branded (Turnstile/reCAPTCHA/null) + trusted cookie (tidak menembus rule critical).
- Perintah CLI: `shield:report`, `shield:rules:list`, `shield:release`, `shield:prune`, `shield:health`,
  `shield:replay`.

## Development

Setup lokal: clone `GanaDev-Com/shield-core` sebagai sibling (`../shield-core`), lalu:

```bash
composer install
composer test        # Pest (Testbench + SQLite in-memory)
composer analyse     # PHPStan + Larastan
composer format-test # Pint
```

> Di CI, `ganadev/shield-core` diambil dari sibling checkout (path repo via `composer config`), sehingga tidak
> perlu menunggu rilis ke Packagist.

## Contoh aplikasi

Lihat [`examples/laravel-demo`](examples/laravel-demo) — aplikasi Laravel untuk mencoba package **setelah
keduanya terbit di Packagist** (`composer require` dari Packagist). Untuk uji manual pre-release gunakan repo
`laravel-test` atau clone kedua package sebagai sibling dan atur path repository. E2E HTTP nyata dapat dijalankan
lokal dengan `bash tools/e2e-smoke.sh`.

## Lisensi

MIT. Dibuat oleh [Ganadev](https://ganadev.com).