# Ganadev Shield — Contoh Aplikasi Laravel

Proyek percobaan untuk menguji `ganadev/shield-core` + `ganadev/laravel-shield` via **path repository**
(perubahan di package langsung terlihat tanpa publish ke Packagist).

## Setup

```bash
cd examples/laravel-demo
cp .env.example .env
php artisan key:generate
composer install
php artisan vendor:publish --provider="Ganadev\Shield\Laravel\ShieldServiceProvider" --tag=shield-config --tag=shield-migrations
php artisan migrate
```

## Menjalankan

```bash
php artisan serve          # http://127.0.0.1:8000
```

## Uji cepat

```powershell
.\test.shield.ps1          # 11 cek end-to-end (block, challenge, cookie)
```

Atau manual:

```bash
curl -i http://127.0.0.1:8000/home                        # 200 normal
curl -i http://127.0.0.1:8000/.env                        # 404 + X-Shield-Blocked: sensitive.env
curl -i "http://127.0.0.1:8000/?file=/root/.aws/credentials"  # 404 + sensitive.aws.credentials
curl -i "http://127.0.0.1:8000/%252e%252e/etc/passwd"     # 404 + traversal.etcpasswd
```

- IP `127.0.0.1` otomatis di-ban setelah diblok → `/home` berikutnya redirect ke `/shield/challenge`.
- `SHIELD_CHALLENGE=null` (default) menampilkan form + tombol Verify offline.
- Untuk widget asli (Turnstile/reCAPTCHA) isi key di `.env` lalu `php artisan config:clear`.
- Reset: `php artisan cache:clear && php artisan shield:release 127.0.0.1`.

## Catatan

- Ban & event tersimpan di SQLite (`database/database.sqlite`).
- `.env` & `database.sqlite` tidak di-commit; buat sendiri saat setup.
- Middleware `SecurityFirewallMiddleware` terpasang sebagai **global middleware** di `bootstrap/app.php`.