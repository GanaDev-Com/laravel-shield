<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Support;

use Ganadev\Shield\Core\Challenge\ChallengeDriverInterface;
use Ganadev\Shield\Core\Clock\SystemClock;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Decision\DecisionEngine;
use Ganadev\Shield\Core\Detection\BehaviorDetector;
use Ganadev\Shield\Core\Detection\ThreatSignatureEngine;
use Ganadev\Shield\Core\Engine\ShieldEngine;
use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Reputation\BanPolicy;
use Ganadev\Shield\Core\Reputation\RiskDecay;
use Ganadev\Shield\Core\Rules\DefaultRules;
use Ganadev\Shield\Core\Rules\RuleRepository;
use Ganadev\Shield\Core\Scoring\RiskScorer;
use Ganadev\Shield\Laravel\Cache\LaravelCacheAdapter;
use Ganadev\Shield\Laravel\Challenge\NullTestDriver;
use Ganadev\Shield\Laravel\Challenge\RecaptchaDriver;
use Ganadev\Shield\Laravel\Challenge\TurnstileDriver;
use Ganadev\Shield\Laravel\Repositories\CachedBanRepository;
use Ganadev\Shield\Laravel\Repositories\EloquentBanRepository;
use Ganadev\Shield\Laravel\Repositories\EloquentEventRepository;
use Ganadev\Shield\Laravel\Trust\DnsCrawlerVerifier;
use Ganadev\Shield\Laravel\Trust\LaravelTrustedCookie;
use Illuminate\Contracts\Container\Container;

/**
 * Builds the framework-agnostic engine from the Laravel container. Kept
 * separate from the service provider so it is easy to unit test and reuse.
 */
final class ShieldResolver
{
    public function __construct(
        private readonly Container $app,
    ) {}

    public function config(): ShieldConfig
    {
        return ShieldConfig::fromArray((array) $this->app->make('config')->get('shield', []));
    }

    public function rules(): RuleRepository
    {
        $config = $this->config();
        $rulesConfig = (array) $this->app->make('config')->get('shield.rules', []);
        $packs = (array) ($rulesConfig['packs'] ?? []);
        unset($rulesConfig['packs']);

        $definitions = DefaultRules::definitions();

        if (($packs['wordpress'] ?? false) === true) {
            $definitions = array_merge($definitions, DefaultRules::wordpressDefinitions());
        }

        if (($packs['injection'] ?? true) === true) {
            $definitions = array_merge($definitions, DefaultRules::injectionDefinitions());
        }

        foreach ($rulesConfig as $override) {
            if (! is_array($override) || ! isset($override['id'])) {
                continue;
            }

            $id = (string) $override['id'];
            foreach ($definitions as $index => $definition) {
                if (($definition['id'] ?? '') === $id) {
                    $definitions[$index] = array_merge($definition, $override);

                    continue 2;
                }
            }
            $definitions[] = $override;
        }

        return RuleRepository::fromArray($definitions);
    }

    public function engine(?ShieldConfig $config = null): ShieldEngine
    {
        $config ??= $this->config();

        return new ShieldEngine(
            config: $config,
            normalizer: new Normalizer,
            signatures: new ThreatSignatureEngine($this->rules()),
            behavior: new BehaviorDetector($this->crawlerVerifier($config)),
            scorer: new RiskScorer,
            decisionEngine: new DecisionEngine,
            banPolicy: new BanPolicy,
            riskDecay: new RiskDecay,
            events: $this->app->make(EloquentEventRepository::class),
            clock: new SystemClock,
            bans: new CachedBanRepository(
                $this->app->make(EloquentBanRepository::class),
                $this->cacheAdapter(),
                $config->banCacheTtlSeconds,
            ),
            trusted: new LaravelTrustedCookie($this->app->make('encrypter')),
        );
    }

    public function crawlerVerifier(?ShieldConfig $config = null): DnsCrawlerVerifier
    {
        $config ??= $this->config();

        return new DnsCrawlerVerifier($this->cacheAdapter(), $config);
    }

    public function cacheAdapter(): LaravelCacheAdapter
    {
        return new LaravelCacheAdapter(
            $this->app->make('cache')->store(),
            $this->config()->appId,
        );
    }

    public function challengeDriver(): ChallengeDriverInterface
    {
        $config = $this->config();

        return match ($config->challengeDriver) {
            '', 'null', 'test' => new NullTestDriver,
            'recaptcha', 'google_recaptcha' => new RecaptchaDriver($this->app->make('config')->get('shield.challenge.recaptcha', [])),
            default => new TurnstileDriver($this->app->make('config')->get('shield.challenge.turnstile', [])),
        };
    }
}
