# Changelog

Semua perubahan penting `ganadev/laravel-shield` didokumentasikan di sini. Format mengikuti
[Keep a Changelog](https://keepachangelog.com/) dan proyek ini mematuhi
[Semantic Versioning](https://semver.org/).

## [1.2.1 - 2026-10-02]

Rilis ini menutup sepuluh temuan audit internal. Semuanya bersifat aditif atau pengetatan default, tidak ada
perubahan pada threshold global maupun semantik signature.

### Changed

- **`logging.events` (boolean) diganti `logging.level` (string).** Recorder menulis
  **setiap request** ke `security_events`, sehingga tabel tumbuh tanpa batas dan baris
  yang dibutuhkan untuk menyetel ambang batas ikut tenggelam. Config sekarang:

  ```diff
   'logging' => [
  -    'events' => true,
  +    'level' => (string) env('SHIELD_LOG_LEVEL', 'suspicious'),
  +    'bypass_events' => (bool) env('SHIELD_LOG_BYPASS_EVENTS', true),
       'retention_days' => (int) env('SHIELD_LOG_RETENTION_DAYS', 30),
   ],
  ```

  `suspicious` (default) menyimpan semua keputusan selain `ALLOW`; `blocked` hanya
  blokir dan ban sementara; `all` menyimpan setiap request untuk debugging singkat.
  Nilai lain ditolak saat boot. `SHIELD_LOG_BYPASS_EVENTS` kini akhirnya terekspos.

  **Catatan upgrade:** `config/shield.php` yang sudah di-publish tidak ikut berubah, jadi
  `'events' => true` menjadi tidak terbaca dan `level` memakai default `suspicious`.
  Tambahkan `'level' => 'all'` eksplisit bila Anda memang mengandalkan pencatatan tiap
  request. Penurunan jumlah event setelah upgrade itu diharapkan.
- **Default `branding.show_rule_id` `true` menjadi `false`.** Halaman blokir tidak lagi
  membocorkan detail signature ke penyerang. Header `X-Shield-Blocked` tetap membawa rule
  id karena itu sinyal operator, dan `rule_id` tetap tersedia di tabel
  `security_events` untuk kebutuhan debugging produksi.

### Ditambahkan

- **Jawaban JSON untuk klien API dan M2M.** Klien mesin tidak bisa merender halaman
  blokir dan akan salah membaca HTML atau redirect sebagai error protokol. Blok dan
  challenge kini otomatis memakai JSON bila request menegosiasikan JSON atau path-nya
  ada di `api.paths`. Browser tetap menerima HTML dan redirect seperti sebelumnya.

  ```dotenv
  SHIELD_API_DETECT_ACCEPT=true
  ```

  Bentuk blokir, status tetap mengikuti `response_code` (default 404) plus header
  `X-Shield-Blocked`:

  ```json
  {
    "error": "request_blocked",
    "app_id": "my-app",
    "rule_id": "sensitive.env",
    "decision": "BLOCK_REQUEST",
    "score": 12
  }
  ```

  `decision` memakai nilai enum yang sama dengan kolom `decision` di
  `security_events` (`ALLOW`, `OBSERVE`, `CHALLENGE`, `BLOCK_REQUEST`, `TEMP_BAN`),
  jadi log dan respons bisa dikorelasikan tanpa tabel pemetaan.

  Bentuk challenge memakai `401` dan header `X-Shield-Challenge: 1`, tanpa redirect,
  karena klien tidak punya browser untuk menyelesaikan Turnstile:

  ```json
  {
    "error": "challenge_required",
    "app_id": "my-app",
    "challenge_url": "https://app.example.com/shield/challenge?redirect=%2Fapi%2Forders"
  }
  ```

  Tambahkan `api.paths` (mis. `/oauth/token`) bila klien Anda tidak mengirim
  `Accept: application/json`.
- **`rules.skip_paths`.** Prefix path yang menonaktifkan pemindaian body dan penilaian
  perilaku, untuk mengurangi false positive pada rich text editor, webhook, dan traffic
  M2M/NAT yang berbagi satu IP. Signature di URI tetap aktif, sehingga payload critical
  tidak pernah bisa lolos lewat jalur yang dikecualikan. Entri harus diawali `/` dan
  bebas query string; `''` dan `'/'` ditolak saat boot.
- **Penjadwalan `shield:prune` otomatis.** `ShieldServiceProvider` mendaftarkan prune
  harian supaya `security_events` tidak tumbuh tanpa batas. Host tetap **wajib**
  menjalankan `php artisan schedule:run` setiap menit. Hapus entri
  `Schedule::command('shield:prune')` milik Anda sendiri agar tidak berjalan dua kali.
- **Baris `Crawler verification` di `shield:health`.** Probe PTR sekali jalan ke IP
  Googlebot yang dikenal untuk membuktikan resolver aplikasi bisa menjawab reverse-DNS.
  Probe bersifat best-effort dan **tidak pernah** mengubah exit code, karena ketersediaan
  DNS adalah properti lingkungan, bukan cacat Shield — resolver bermasalah di CI tidak
  boleh menggagalkan pipeline. Baris disembunyikan bila
  `bots.verification.enabled` dimatikan.
- **Deteksi posisi middleware pada `LaravelTrustedCookie`.** Bila cookie trusted diterima
  dalam bentuk sudah ter-decrypt, adapter mencatat satu peringatan ke log application.
  Gejalanya middleware dipindahkan ke group `web`, tempat `EncryptCookies` berjalan lebih
  dulu sehingga setiap pengguna yang sudah lolos challenge akan ditanya ulang terus.
  Peringatan hanya ditulis sekali per instance.
- **`Content-Type: text/html` eksplisit pada halaman blokir.** Sebelumnya header itu
  tidak pernah di-set, sehingga bentuk respons bisa bergantung pada default Symfony.
- **`SHIELD_LOG_LEVEL` dan `SHIELD_API_DETECT_ACCEPT`** sebagai env untuk key config
  yang baru. Daftar `rules.skip_paths` dan `api.paths` sengaja **tidak** memakai env
  karena parsing daftar dari string ber-koma mudah salah set; tulis langsung sebagai
  array di config.

### Diperbaiki

- **Constraint `ganadev/shield-core` diperketat ke `^1.2.1`.** Rilis ini memakai API
  config core yang baru diperkenalkan di core `1.2.1` — `skip_paths`, `api.paths`, dan
  `logging.level` — sementara constraint sebelumnya masih `^1.0`. Akibatnya `composer`
  menganggap core `1.2.0` (yang belum punya properti tersebut) memenuhi syarat, lalu
  `SecurityFirewallMiddleware` gagal saat runtime ketika membaca `$config->skipPaths`.
  `^1.2.1` membuat `composer update` ikut menaikkan core, jadi kedua package **wajib**
  naik ke `1.2.1` bersamaan.
- **Fallback view halaman blokir ikut mengikuti default privacy.** `blocked.blade.php`
  memakai `?? true` untuk `branding.show_rule_id`, sehingga key yang hilang dari array
  branding akan tetap menampilkan rule id. Sekarang `?? false`, konsisten dengan default
  config yang baru.
- **`safeRedirect()` merusak query string.** `ChallengeController` memanggil `e()` pada
  path tujuan, yang mengubah `&` menjadi `&amp;`, dan itu mendarat apa adanya di header
  `Location`. Setiap redirect dengan lebih dari satu parameter terpotong. Path kini
  dikembalikan apa adanya; escaping tetap terjadi di lapisan Blade saat render.
- **Pencocokan prefix path dinormalisasi.** `Request::path()` mengembalikan path tanpa
  leading `/` sementara setiap prefix hasil konfigurasi diawali `/`, sehingga tanpa
  normalisasi tidak ada satu pun prefix yang akan cocok. Pencocokan juga mencegah
  match silang seperti `/apifoo` terhadap prefix `/api`.

## [1.2.0 - 2026-10-01]

Nomor `1.1.0` dilewati: rilis itu disiapkan tapi tidak pernah diberi tag Git, jadi tidak pernah terbit dan tidak
ada versi yang perlu di-deprecate.

Perubahan pada rilis ini seluruhnya bersifat aditif: tidak ada threshold global maupun semantik signature yang
berubah.

### Changed

- **Default `bots.mode` berubah dari `challenge` menjadi `observe`.** Default sebelumnya
  bisa merusak SEO/AI-crawler: begitu reverse-DNS atau CIDR gagal — DNS bermasalah,
  resolver diblokir, atau domain crawler belum terdaftar — crawler resmi diklaim palsu
  lalu mendapat `403/419`, padahal `/robots.txt` dan `/sitemap.xml` harus selalu bisa
  diakses. `mode` global sudah `observe` sejak awal, jadi ini juga
  menyelaraskan `bots.mode` dengan falsafah dan dokumentasi package.

  Perilaku opt-in tetap tersedia: set `SHIELD_BOT_MODE=challenge` (atau
  `bots.mode` di config) untuk mengembalikan challenge pada crawler tak terverifikasi.
  Naikkan hanya setelah `shield:health` dan log `unverified_crawler_claim_*` menunjukkan
  verifikasi berjalan benar.

  Yang berubah: crawler tak terverifikasi sekarang dilayani dan hanya dicatat
  (`SIGNAL_UNVERIFIED_CRAWLER_CLAIM` tetap masuk skor), bukan di-challenge.

### Ditambahkan

- **Peringatan trusted proxy saat boot.** `ShieldServiceProvider` mencatat warning ketika
  `mode` `challenge`/`enforce`, `app.url` menunjuk host publik, dan trusted proxies belum
  dikonfigurasi. Sebelum ini masalah baru terlihat kalau somebody menjalankan `shield:health`.
  Dampaknya nyata: tanpa trusted proxies semua klien terlihat sebagai IP proxy sehingga
  rate limit per-IP dan ban tidak efektif.
- **`TrustedProxyInspector`.** Membaca konfigurasi proxy dari static `TrustProxies`
  (protected, tanpa getter publik). `Request::getTrustedProxies()` hanya mencerminkan
  request berjalan, jadi dari CLI selalu kosong dan tidak bisa dipakai sebagai sumber
  konfigurasi.

### Diperbaiki

- **`shield:health` tidak lagi false negative pada trusted proxy.** Sebelumnya tabel hanya
  menampilkan "terdeteksi" lalu keluar sebelum membaca konfigurasi, sehingga kondisi
  berbahaya (header forwarded ada, trusted proxies kosong) tidak pernah diberi warning.
  Sekarang kondisi itu eksplisit, plus deteksi berbasis host publik.
- **Validasi `allowlist.paths`.** Nilai `''` dan `'/'` ditolak saat boot dengan
  `InvalidConfigException`. Keduanya membuat **seluruh request ter-allowlist** karena
  pencocokan memakai `str_starts_with()`, jadi satu karakter salah tulis mematikan seluruh
  proteksi secara senyap. Entri juga harus diawali `/` dan bebas query string, serta
  di-trim. Critical signature tetap tidak bisa di-bypass (guard `hasCriticalMatch`).

## [1.0.1 - 2026-10-01]

Perubahan pada rilis ini semuanya bersifat aditif: tidak ada verdict, threshold, atau
default yang berubah. Tidak ada breaking change pada API publik.

### Ditambahkan

- **Exemption route admin pada firewall.** `SecurityFirewallMiddleware` kini menghormati
  `shield.admin.prefix`. Sebelumnya hanya prefix hardcoded `shield/` yang dilewati, jadi
  admin panel yang dipindahkan ke prefix lain ikut dipindai firewall — operator bisa
  terkunci dari panel yang justru dipakai untuk mencabut ban. Challenge route di
  `/shield/challenge` tetap dikecualikan seperti sebelumnya.
- **`admin_authorize_warning` di health endpoint.** `GET {prefix}/health` kini melaporkan
  warning ketika `admin.enabled` true tapi `admin.authorize` kosong, karena dalam kondisi
  itu setiap user terautentikasi bisa mengelola ban.

### Diperbaiki

- **Race condition pada counter cache.** `LaravelCacheAdapter::increment()` memakai
  `add()` atomik. Nilai pertama disimpan sebagai `1`, bukan `0`, sehingga hitungan yang
  dilaporkan tidak meleset satu pada panggilan pertama.