<?php

declare(strict_types=1);

return [
    'enabled' => env('SHIELD_ENABLED', true),
    'mode' => env('SHIELD_MODE', 'observe'),
    'app_id' => env('SHIELD_APP_ID', 'my-app'),
    'response_code' => (int) env('SHIELD_RESPONSE_CODE', 404),
    'decode_depth' => 2,
    'fail_mode' => env('SHIELD_FAIL_MODE', 'open'),

    'thresholds' => [
        'challenge' => (int) env('SHIELD_THRESHOLD_CHALLENGE', 10),
        'ban' => (int) env('SHIELD_THRESHOLD_BAN', 20),
        'strong_ban' => (int) env('SHIELD_THRESHOLD_STRONG_BAN', 30),
    ],

    'ban' => [
        'durations' => [15, 60, 360, 1440],
    ],

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

    'behavior' => [
        'unique_uri_limit' => (int) env('SHIELD_BEHAVIOR_UNIQUE_URI_LIMIT', 25),
        'window_seconds' => (int) env('SHIELD_BEHAVIOR_WINDOW_SECONDS', 60),
        'not_found_limit' => (int) env('SHIELD_BEHAVIOR_NOT_FOUND_LIMIT', 20),
        'missing_referer_signal' => (bool) env('SHIELD_BEHAVIOR_MISSING_REFERER', true),
        'suspicious_user_agents' => [],
        'path_rate_limit' => (int) env('SHIELD_BEHAVIOR_PATH_RATE_LIMIT', 30),
        'sensitive_path_rate_limit' => (int) env('SHIELD_BEHAVIOR_SENSITIVE_PATH_RATE_LIMIT', 8),
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

    'bots' => [
        'mode' => env('SHIELD_BOT_MODE', 'challenge'),
        'unverified_claim_signal' => (int) env('SHIELD_BOT_UNVERIFIED_CLAIM_SIGNAL', 4),
        'verification' => [
            'enabled' => (bool) env('SHIELD_BOT_VERIFICATION_ENABLED', true),
            'ttl_hours' => (int) env('SHIELD_BOT_VERIFICATION_TTL_HOURS', 24),
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
            'ip_ranges' => [
                // Demo lokal: anggap 127.0.0.0/8 sebagai IP terverifikasi Googlebot
                // sehingga UA "Googlebot" dari localhost lolos (SEO-safe demo).
                'googlebot' => ['127.0.0.0/8'],
            ],
        ],
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

    'rules' => [
        'packs' => [
            'wordpress' => (bool) env('SHIELD_RULES_PACK_WORDPRESS', false),
            'injection' => (bool) env('SHIELD_RULES_PACK_INJECTION', true),
        ],
    ],

    'inspection' => [
        'body' => [
            'enabled' => (bool) env('SHIELD_INSPECTION_BODY_ENABLED', true),
            'max_bytes' => (int) env('SHIELD_INSPECTION_BODY_MAX_BYTES', 65536),
        ],
    ],

    'logging' => [
        'events' => true,
        'retention_days' => (int) env('SHIELD_LOG_RETENTION_DAYS', 30),
    ],

    'admin' => [
        'enabled' => (bool) env('SHIELD_ADMIN_ENABLED', false),
        'middleware' => ['web', 'auth'],
        'prefix' => 'shield',
    ],

    'allowlist' => [
        'hosts' => [],
        'paths' => [],
        'ips' => [],
    ],

    'trusted' => [
        'enabled' => true,
        'ttl_minutes' => (int) env('SHIELD_TRUSTED_TTL_MINUTES', 60),
    ],

    'performance' => [
        'max_uri_length' => (int) env('SHIELD_MAX_URI_LENGTH', 2048),
        'ban_cache_ttl_seconds' => (int) env('SHIELD_BAN_CACHE_TTL', 30),
    ],

    'escalation' => [
        'step' => 5,
    ],

    'privacy' => [
        'sensitive_query_parameters' => ['token', 'password', 'passwd', 'key', 'secret', 'code', 'auth'],
    ],

    'rule_version' => '1.0.0',
];
