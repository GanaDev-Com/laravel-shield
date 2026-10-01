# Changelog

Semua perubahan penting `ganadev/laravel-shield` didokumentasikan di sini. Format mengikuti
[Keep a Changelog](https://keepachangelog.com/) dan proyek ini mematuhi
[Semantic Versioning](https://semver.org/).

## [1.1.0 - 2026-10-01]

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