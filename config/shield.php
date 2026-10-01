<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Aktifkan Ganadev Shield
    |--------------------------------------------------------------------------
    |
    | Master switch. Saat bernilai false, middleware dilewati sepenuhnya dan
    | tidak ada event keamanan yang tercatat. Hanya untuk debugging atau saat
    | aplikasi belum siap produksi.
    |
    */

    'enabled' => env('SHIELD_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Mode Operasi
    |--------------------------------------------------------------------------
    |
    | Menentukan seberapa tegas keputusan firewall dijalankan.
    |
    | "observe"  : keputusan tetap dihitung dan dicatat, tapi response asli
    |              diteruskan. Ini default yang aman untuk produksi. Awali di
    |              sini, pantau lewat `php artisan shield:report`, lalu naikkan.
    | "challenge": signature critical diblokir, ban menjadi challenge, sisanya
    |              mengikuti skor. Ban tidak pernah terbit.
    | "enforce"  : seluruh keputusan dijalankan apa adanya, termasuk ban.
    |
    */

    'mode' => env('SHIELD_MODE', 'observe'),

    /*
    |--------------------------------------------------------------------------
    | Identitas Aplikasi
    |--------------------------------------------------------------------------
    |
    | Namespace untuk seluruh key cache: ban, counter perilaku, dan verifikasi
    | crawler. Wajib unik bila satu instance Redis atau Memcached dipakai
    | beberapa aplikasi, jika tidak ban dan counter antar aplikasi saling
    | menimpa.
    |
    */

    'app_id' => env('SHIELD_APP_ID', 'my-app'),

    /*
    |--------------------------------------------------------------------------
    | Respons dan Normalisasi URI
    |--------------------------------------------------------------------------
    |
    | "response_code" : status HTTP saat request diblokir. 404 membuat blokir
    |                   tidak berbeda dari halaman tidak ada, sehingga attacker
    |                   tidak mendapat informasi path mana yang ada. 403 lebih
    |                   jujur tapi membocorkan keberadaan path. 429 juga wajar.
    | "decode_depth"  : berapa kali query dan body di-decode sebelum dicocokkan
    |                   ke rule. Ini yang menangkap payload ber-encode ganda.
    |                   Nilai lebih besar lebih menyeluruh tapi lebih mahal, dan
    |                   harus di antara 0 sampai 3.
    |
    */

    'response_code' => (int) env('SHIELD_RESPONSE_CODE', 404),
    'decode_depth' => 2,

    /*
    |--------------------------------------------------------------------------
    | Perilaku Saat Penyimpanan Gagal
    |--------------------------------------------------------------------------
    |
    | Apa yang terjadi kalau penyimpanan ban tidak bisa diakses, misalnya
    | database sedang down.
    |
    | "open"  : request diteruskan, hanya dicatat sebagai infrastruktur
    |           yang terganggu. Penyerang lolos saat server sedang sakit.
    | "closed": semua request diblokir sampai penyimpanan pulih. Melindungi
    |           data, tapi seluruh traffic ikut terblokir, termasuk pengunjung
    |           yang sah.
    |
    | "closed" lebih tepat untuk sistem yang menyimpan data sensitif di balik
    | firewall. "open" lebih cocok untuk situs yang mengutamakan ketersediaan.
    | Default "open" dipilih karena kesalahan memilih "closed" jauh lebih sulit
    | daripada kesalahan sebaliknya: begitu diterapkan, tidak ada yang ingat
    | untuk mencabutnya saat insiden.
    |
    */

    'fail_mode' => env('SHIELD_FAIL_MODE', 'open'),

    /*
    |--------------------------------------------------------------------------
    | Ambang Batas Skor Risiko
    |--------------------------------------------------------------------------
    |
    | Skor risiko total, yaitu signature plus perilaku plus eskalasi, dibandingkan
    | dengan ketiga angka ini:
    |
    |   di bawah "challenge" : ALLOW, atau OBSERVE saat mode observe
    |   di atas  "challenge" : CHALLENGE
    |   di atas  "ban"       : TEMP_BAN
    |   di atas  "strong_ban": TEMP_BAN dengan durasi terpanjang
    |
    | Ketiganya harus naik berurutan. Nilai sama atau turun akan ditolak saat
    | boot, karena membuat keputusan tidak dapat diprediksi. Menurunkan angka
    | "challenge" berarti lebih sedikit challenge yang terbit, menaikkan "ban"
    | membuat ban lebih jarang tapi lebih lambat.
    |
    */

    'thresholds' => [
        'challenge' => (int) env('SHIELD_THRESHOLD_CHALLENGE', 10),
        'ban' => (int) env('SHIELD_THRESHOLD_BAN', 20),
        'strong_ban' => (int) env('SHIELD_THRESHOLD_STRONG_BAN', 30),
    ],

    /*
    |--------------------------------------------------------------------------
    | Durasi Ban Bertingkat
    |--------------------------------------------------------------------------
    |
    | Durasi ban dalam MENIT, dipilih berdasarkan jumlah pelanggaran yang
    | berulang. Pelanggaran pertama memakai elemen pertama, yang kedua memakai
    | elemen kedua, dan seterusnya. Setelah melewati panjang daftar, durasi
    | terakhir terus dipakai.
    |
    | Jumlah pelanggaran tidak dihapus saat ban dilepas, sehingga yang melanggar
    | lagi akan naik ke durasi berikutnya. Catatan: nilai ini berkurang satu
    | setiap 24 jam tanpa request, jadi IP yang terlihat lama diam akan mulai
    | lagi dari durasi terpendek.
    |
    */

    'ban' => [
        'durations' => [15, 60, 360, 1440],
    ],

    /*
    |--------------------------------------------------------------------------
    | Driver Challenge
    |--------------------------------------------------------------------------
    |
    | Provider yang dipakai memverifikasi request yang kena challenge:
    |
    | "turnstile" : Cloudflare Turnstile, ini default.
    | "recaptcha" : Google reCAPTCHA.
    | "null"      : tanpa verifikasi pihak ketiga. Challenge dilewati begitu
    |              saja, jadi tidak memblokir apa pun. Hanya untuk test, jangan
    |              dipakai di produksi.
    |
    | Driver yang dipilih membaca site_key dan secret_key dari environment.
    | Secret tidak pernah disimpan ke database maupun ditulis ke log.
    |
    */

    'challenge' => [
        'driver' => env('SHIELD_CHALLENGE', 'turnstile'),
        'turnstile' => [
            'site_key' => env('SHIELD_TURNSTILE_SITE_KEY', ''),
            'secret_key' => env('SHIELD_TURNSTILE_SECRET_KEY', ''),
            'verify_url' => env('SHIELD_TURNSTILE_VERIFY_URL', 'https://challenges.cloudflare.com/turnstile/v0/siteverify'),
        ],
        'recaptcha' => [
            'site_key' => env('SHIELD_RECAPTCHA_SITE_KEY', ''),
            'secret_key' => env('SHIELD_RECAPTCHA_SECRET_KEY', ''),
            'verify_url' => env('SHIELD_RECAPTCHA_VERIFY_URL', 'https://www.google.com/recaptcha/api/siteverify'),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Deteksi Perilaku
    |--------------------------------------------------------------------------
    |
    | Signal perilaku tidak terlihat dari satu request tunggal, melainkan dari
    | pola lintas request dalam jendela waktu "window_seconds". Counter
    | disimpan di cache dengan key yang di-namespace oleh "app_id".
    |
    | Crawler yang berhasil diverifikasi lewat reverse-DNS dan CIDR membuat
    | seluruh counter perilaku dinolkan. Googlebot asli dengan demikian tetap
    | bisa crawl agresif tanpa pernah kena challenge, dan hanya signature
    | malicious yang tetap berlaku untuknya.
    |
    */

    'behavior' => [
        /*
         * Jumlah URI berbeda dalam satu jendela sebelum ditandai burst. Makin
         * rendah, makin sensitif deteksi enumerasi, tapi crawler eksploratif
         * dan sebagian load balancer ikut ter-flag.
         */
        'unique_uri_limit' => (int) env('SHIELD_BEHAVIOR_UNIQUE_URI_LIMIT', 25),

        /*
         * Panjang jendela waktu counter perilaku, dalam detik. Pola yang
         * tersebar di luar jendela ini tidak terhitung sebagai satu pola.
         */
        'window_seconds' => (int) env('SHIELD_BEHAVIOR_WINDOW_SECONDS', 60),

        /*
         * Jumlah respons 404 dalam satu jendela sebelum ditandai enumerasi path.
         */
        'not_found_limit' => (int) env('SHIELD_BEHAVIOR_NOT_FOUND_LIMIT', 20),

        /*
         * POST tanpa referer dianggap mencurigakan. Nonaktifkan kalau aplikasi
         * memakai client yang memang tidak mengirim referer, misalnya API
         * mobile atau integrasi server ke server.
         */
        'missing_referer_signal' => (bool) env('SHIELD_BEHAVIOR_MISSING_REFERER', true),

        /*
         * Tambahkan user agent di sini untuk menaikkan signal curiga pada UA
         * tertentu. Dicocokkan dengan substring, case-insensitive.
         */
        'suspicious_user_agents' => [],

        /*
         * User agent alat keamanan yang dikenali, seperti sqlmap, nikto, dan
         * wpscan. Signal-nya lebih kuat daripada sekadar mencurigakan. Hapus
         * dari daftar ini bila aplikasi Anda memang sering diakses scanner
         * sah, misalnya pentest terjadwal, agar tidak langsung di-ban.
         */
        'scanner_user_agents' => [
            'sqlmap',
            'nikto',
            'metasploit',
            'wpscan',
            'dirbuster',
            'gobuster',
            'masscan',
            'nmap',
            'nessus',
            'acunetix',
            'x00c',
            'zgrab',
            'httpx',
        ],
        'scanner_ua_signal' => (int) env('SHIELD_BEHAVIOR_SCANNER_UA_SIGNAL', 4),

        /*
         * Batas request per path biasa dalam satu jendela.
         */
        'path_rate_limit' => (int) env('SHIELD_BEHAVIOR_PATH_RATE_LIMIT', 30),

        /*
         * Batas request per path sensitif. Lebih rendah karena path seperti
         * /login adalah target brute-force, bukan lalu lintas normal.
         */
        'sensitive_path_rate_limit' => (int) env('SHIELD_BEHAVIOR_SENSITIVE_PATH_RATE_LIMIT', 8),

        /*
         * Path yang dianggap sensitif. Dicocokkan sebagai prefix, jadi "/admin"
         * sekaligus mencakup "/admin/login".
         */
        'sensitive_paths' => [
            '/login',
            '/wp-login.php',
            '/admin/login',
            '/administrator/',
            '/api/login',
            '/api/auth',
            '/user/login',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Penanganan Crawler
    |--------------------------------------------------------------------------
    |
    | Berlaku khusus untuk request yang mengklaim menjadi crawler lewat
    | User-Agent. Berbeda dari "mode" di atas, pengaturan ini tidak menyentuh
    | request pengguna biasa.
    |
    | "off"      : klaim crawler diabaikan sepenuhnya, tanpa signal apa pun.
    | "observe"  : crawler yang gagal diverifikasi tetap dilayani, hanya
    |              dicatat. Ini default aman untuk SEO, karena /robots.txt dan
    |              /sitemap.xml tidak ikut terblokir saat DNS bermasalah.
    | "challenge": crawler yang mengklaim nama resmi tapi gagal verifikasi
    |              lewat reverse-DNS atau CIDR selalu kena challenge.
    |
    | Naikkan ke "challenge" hanya setelah memastikan verifikasi crawler
    | benar-benar bekerja. DNS yang bermasalah akan menandai crawler sah
    | sebagai palsu, dan akibatnya indeksasi situs terganggu.
    |
    */

    'bots' => [

        /*
         * Mode penanganan crawler. Penjelasan lengkap ada di banner di atas.
         */
        'mode' => env('SHIELD_BOT_MODE', 'observe'),

        /*
         * Skor yang ditambahkan saat crawler gagal diverifikasi. Pada mode
         * "observe" signal ini tetap dihitung, jadi kalau nilainya cukup tinggi
         * atau digabung dengan signal mencurigakan lain, request tetap bisa
         * masuk challenge lewat scoring normal.
         */
        'unverified_claim_signal' => (int) env('SHIELD_BOT_UNVERIFIED_CLAIM_SIGNAL', 4),

        'verification' => [

            /*
             * Verifikasi crawler lewat reverse-DNS dan konfirmasi IP maju.
             *
             * PENTING: mematikan ini BUKAN membuat crawler dianggap sah.
             * Justru sebaliknya. Tanpa verifikasi, setiap klaim crawler resmi
             * dianggap palsu. Karena itu, kalau verification dimatikan, pastikan
             * "mode" di atas tetap "observe", jika tidak semua bot akan kena
             * challenge termasuk crawler sah.
             */
            'enabled' => (bool) env('SHIELD_BOT_VERIFICATION_ENABLED', true),

            /*
             * Lama hasil verifikasi disimpan di cache, dalam jam. IP crawler
             * yang sama tidak perlu lookup DNS berulang. Naikkan kalau server
             * DNS Anda berat, turunkan kalau lebih jarang pergantian IP.
             */
            'ttl_hours' => (int) env('SHIELD_BOT_VERIFICATION_TTL_HOURS', 24),

            /*
             * Hostname resmi yang boleh dipakai tiap crawler. Pencocokan
             * berbasis suffix dengan titik awal sebagai batas label, jadi
             * ".google.com" mencakup "crawl-66-249-79-12.google.com" tetapi
             * tidak mencakup "evil-google.com".
             */
            'hostnames' => [
                'googlebot' => ['.googlebot.com', '.google.com'],
                'bingbot' => ['.search.msn.com'],
                'yandexbot' => ['.yandex.ru', '.yandex.net'],
                'baiduspider' => ['.baidu.com', '.baidu.jp'],
                'duckduckbot' => ['.duckduckgo.com'],
                'ahrefsbot' => ['.ahrefs.com'],
                'semrushbot' => ['.semrush.com'],
                'dotbot' => ['.moz.com'],
                'ccbot' => ['.cc'],
            ],

            /*
             * CIDR resmi per crawler. Kalau IP ada di sini, crawler terverifikasi
             * tanpa lookup DNS sama sekali. Berguna di lingkungan yang tidak boleh
             * melakukan reverse-DNS.
             */
            'ip_ranges' => [],
        ],

        /*
         * Nama crawler yang dikenali dari User-Agent, dipetakan ke nama canonical
         * di "verification.hostnames" atau "ip_ranges" di atas. User agent yang
         * tidak ada di sini tidak pernah dianggap bot sama sekali, berapa pun
         * IP-nya.
         */
        'known_agents' => [
            'googlebot',
            'bingbot',
            'yandexbot',
            'baiduspider',
            'duckduckbot',
            'ahrefsbot',
            'semrushbot',
            'mj12bot',
            'dotbot',
            'bytespider',
            'ccbot',
            'gptbot',
            'chatgpt-user',
            'claudebot',
            'anthropic',
            'openai',
            'oai-searchbot',
            'perplexitybot',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Paket Rules
    |--------------------------------------------------------------------------
    |
    | Dua paket signature bawaan yang bisa diaktifkan:
    |
    | "injection" : SQLi, XSS, LFI dan SSI, command injection pada query dan
    |               body. Default aktif karena hampir selalu relevan.
    | "wordpress" : signature khusus WordPress seperti xmlrpc.php,
    |               wp-config.php, dan probe plugin. Default mati karena hanya
    |               relevan di situs WordPress. Nyalakan hanya kalau aplikasi
    |               memang menjalankan WordPress, jika tidak bisa menambah
    |               false positive pada path yang kebetulan mirip.
    |
    | Keduanya independen, mengaktifkan WordPress tidak mematikan injection.
    |
    */

    'rules' => [
        'packs' => [
            'wordpress' => (bool) env('SHIELD_RULES_PACK_WORDPRESS', false),
            'injection' => (bool) env('SHIELD_RULES_PACK_INJECTION', true),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Inspeksi Body Request
    |--------------------------------------------------------------------------
    |
    | Signature juga dicocokkan ke body request, bukan hanya URI. Body tidak
    | pernah disimpan ke database maupun log, hanya kecocokan rule yang
    | direkam, supaya tidak ada data pengguna atau password yang bocor ke
    | storage sendiri.
    |
    | "max_bytes" : batas ukuran body yang dibaca. Body yang lebih besar dipotong
    | dan ditandai oversized. Naikkan hanya kalau payload yang ingin ditangkap
    | memang panjang. Menaikannya menambah memori dan latensi per request.
    |
    | Body multipart untuk upload file tidak pernah di-buffer.
    |
    */

    'inspection' => [
        'body' => [
            'enabled' => (bool) env('SHIELD_INSPECTION_BODY_ENABLED', true),
            'max_bytes' => (int) env('SHIELD_INSPECTION_BODY_MAX_BYTES', 65536),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Pencatatan Event
    |--------------------------------------------------------------------------
    |
    | "events"         : simpan setiap keputusan firewall ke tabel
    |                   "security_events". Nilainya selalu true karena data ini
    |                   adalah bahan utama untuk menyetel ambang batas dan
    |                   membaca kejadian setelah insiden.
    | "retention_days" : umur event sebelum bisa dipangkas. Penghapusan tidak
    |                   terjadi otomatis, jadi jalankan `php artisan shield:prune`
    |                   dari scheduler supaya tabel tidak tumbuh tanpa batas.
    |
    */

    'logging' => [
        'events' => true,
        'retention_days' => (int) env('SHIELD_LOG_RETENTION_DAYS', 30),
    ],

    /*
    |--------------------------------------------------------------------------
    | Panel Admin
    |--------------------------------------------------------------------------
    |
    | Antarmuka HTTP untuk melihat event, mengelola ban, dan mengecek kesehatan
    | komponen. Default nonaktif karenainnings membuka data reputasi pengguna.
    |
    | "middleware" : middleware yang melindungi route admin. Default "web" dan
    |               "auth" berarti harus login lebih dulu. Jangan dikosongkan
    |               kecuali Anda membatasi akses lewat cara lain seperti IP
    |               allowlist atau VPN.
    | "authorize"  : nama ability atau permission yang wajib dimiliki user,
    |               contoh "manage-shield". Dikosongkan berarti setiap user
    |               yang sudah terautentikasi boleh mengelola ban, yang hanya
    |               wajar di lingkungan lokal. Endpoint health memberi
    |               peringatan kalau kombinasi ini aktif.
    | "prefix"     : prefix URL panel. Prefix ini sekaligus nama yang dikenali
    |               firewall middleware agar request ke panel tidak dipindai.
    |
    */

    'admin' => [
        'enabled' => (bool) env('SHIELD_ADMIN_ENABLED', false),
        'middleware' => ['web', 'auth'],
        'authorize' => env('SHIELD_ADMIN_AUTHORIZE', ''),
        'prefix' => 'shield',
    ],

    /*
    |--------------------------------------------------------------------------
    | Allowlist Request
    |--------------------------------------------------------------------------
    |
    | Request yang cocok melompat seluruh proteksi firewall, kecuali signature
    | critical seperti .env atau traversal yang selalu diblokir.
    |
    | "paths" harus prefix spesifik yang diawali "/", misalnya "/admin" atau
    | "/api/v2". Nilai kosong dan "/" ditolak saat boot, karena pencocokan
    | memakai str_starts_with sehingga keduanya akan meng-allowlist seluruh
    | request tanpa memberi tanda apa pun. Untuk meng-allowlist satu host
    | penuh, pakai "hosts" atau "ips".
    |
    | Perhatikan bahwa path dicocokkan sebagai prefix, jadi "/admin" juga
    | mencakup "/administrator". Tulis "/admin/" bila hanya ingin direktori
    | admin-nya saja.
    |
    */

    'allowlist' => [
        'hosts' => [],
        'paths' => [],
        'ips' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Trusted Cookie
    |--------------------------------------------------------------------------
    |
    | Setelah challenge berhasil, cookie diberikan agar request berikutnya tidak
    | ditanya berulang. Cookie terikat pada IP, user agent, dan prefix jaringan
    | asal, sehingga tidak bisa dipinjam dari mesin atau IP lain.
    |
    | "ttl_minutes" : umur cookie dalam menit. Makin panjang, makin jarang user
    | ditanya ulang, tapi makin lama cookie itu tetap berlaku di browser yang
    | tertinggal di komputer bersama. Nilai moderat seperti 30 sampai 120
    | biasanya cukup.
    |
    | Trusted cookie hanya melewati keputusan challenge. Ban aktif dan
    | signature critical tetap ditegakkan.
    |
    */

    'trusted' => [
        'enabled' => true,
        'ttl_minutes' => (int) env('SHIELD_TRUSTED_TTL_MINUTES', 60),
    ],

    /*
    |--------------------------------------------------------------------------
    | Performa
    |--------------------------------------------------------------------------
    |
    | "max_uri_length"       : URI yang lebih panjang dipotong sebelum dicocokkan
    |                         ke rule. Mencegah request raksasa memakai CPU
    |                         hanya untuk diproses. Naikkan kalau aplikasi memang
    |                         punya query string panjang seperti filter
    |                         pencarian, tapi perhatikan ini mengurangi deteksi
    |                         payload yang sengaja menyamar panjang.
    | "ban_cache_ttl_seconds": lama ban aktif disimpan di cache sebelum dibaca
    |                         dari database. Makin besar, makin banyak query ke
    |                         database yang dihemat, tapi ban baru bisa terlambat
    |                         terlihat sampai TTL habis.
    |
    */

    'performance' => [
        'max_uri_length' => (int) env('SHIELD_MAX_URI_LENGTH', 2048),
        'ban_cache_ttl_seconds' => (int) env('SHIELD_BAN_CACHE_TTL', 30),
    ],

    /*
    |--------------------------------------------------------------------------
    | Eskalasi Ban
    |--------------------------------------------------------------------------
    |
    | Pengali untuk pelanggaran berulang. Setiap kali jumlah pelanggaran naik,
    | skor risiko bertambah "step" dikali jumlah pelanggaran, dibatasi maksimal
    | lima langkah. Efeknya, request yang sebelumnya hanya kena challenge bisa
    | naik jadi ban tanpa perlu aturan tambahan.
    |
    | Berlaku hanya bila request itu sudah punya violation, yaitu signature
    | yang cocok atau signal perilaku yang kuat. Signal lemah seperti user
    | agent mencurigakan atau referer hilang tidak memicu eskalasi, supaya
    | pengguna biasa tidak tiba-tiba ter-ban.
    |
    | Perlu dicatat: eskalasi memakai jumlah pelanggaran dari ban yang masih
    | aktif. Setiap request tanpa ban aktif dihitung sebagai pelanggaran 0,
    | jadi request pertama dari sebuah IP belum pernah mendapat tambahan skor
    | dari eskalasi, apa pun nilai "step" di sini.
    |
    */

    'escalation' => [
        'step' => 5,
    ],

    /*
    |--------------------------------------------------------------------------
    | Privasi
    |--------------------------------------------------------------------------
    |
    | Nama parameter query yang nilainya disamarkan sebelum event disimpan,
    | misalnya "?token=abc" menjadi "?token=***". Mencegah kredensial bocor ke
    | tabel security_events dan ke log aplikasi.
    |
    | Pencocokan key bersifat case-insensitive dan sudah menangani key yang
    | di-percent-encode, sehingga "access%5Ftoken" juga ikut disamarkan.
    | Tambahkan nama parameter spesifik aplikasi di sini, misalnya "api_key"
    | atau "jwt".
    |
    | Parameter yang tidak ada di daftar ini akan tersimpan apa adanya,
    | pastikan tidak ada parameter sensitif yang lupa didaftarkan.
    |
    */

    'privacy' => [
        'sensitive_query_parameters' => ['token', 'password', 'passwd', 'key', 'secret', 'code', 'auth'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Versi Rules
    |--------------------------------------------------------------------------
    |
    | Versi signature aktif, dicatat pada setiap security event. Berguna untuk
    | mengurai apakah sebuah deteksi berasal dari versi signature lama setelah
    | rules diperbarui. Naikkan setiap kali signature bawaan berubah.
    |
    */

    'rule_version' => '1.0.0',

    /*
    |--------------------------------------------------------------------------
    | View
    |--------------------------------------------------------------------------
    |
    | View untuk halaman blokir dan halaman challenge. Paket menyediakan default
    | ber-branding; publish dengan
    | `php artisan vendor:publish --tag=shield-views` untuk mengustom sendiri.
    |
    */

    'views' => [
        'blocked' => env('SHIELD_VIEW_BLOCKED', 'shield::blocked'),
        'challenge' => env('SHIELD_VIEW_CHALLENGE', 'shield::challenge'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Branding
    |--------------------------------------------------------------------------
    |
    | Tampilan halaman yang dibuat sendiri, yaitu judul, warna aksen, dan warna
    | latar. Warna bebas format hex.
    |
    | "show_rule_id" : tampilkan ID rule yang cocok di halaman blokir. Sangat
    |                  membantu saat penyetelan, tapi membocorkan detail
    |                  signature ke penyerang. Matikan di produksi kalau ini
    |                  dianggap sensitif.
    |
    */

    'branding' => [
        'title' => env('SHIELD_BRANDING_TITLE', 'Ganadev Laravel Shield'),
        'accent_color' => env('SHIELD_BRANDING_ACCENT', '#22d3ee'),
        'background_color' => env('SHIELD_BRANDING_BG', '#0b1220'),
        'show_rule_id' => (bool) env('SHIELD_BRANDING_SHOW_RULE_ID', true),
    ],
];
