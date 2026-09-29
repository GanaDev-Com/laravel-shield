{{-- Ganadev Shield — challenge page. Data: driver, siteKey, testToken, csrfToken, redirect, error, branding. --}}
@php
    $accent = $branding['accent_color'] ?? '#22d3ee';
    $bg = $branding['background_color'] ?? '#0b1220';
    $title = $branding['title'] ?? 'Ganadev Laravel Shield';
@endphp
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Security Check — {{ $title }}</title>
<style>
  :root { --accent: {{ $accent }}; --bg: {{ $bg }}; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; color: #e6edf3;
    background:
      radial-gradient(1200px 600px at 50% -10%, {{ $accent }}22 0%, transparent 60%),
      linear-gradient(160deg, var(--bg) 0%, #05080f 100%);
    padding: 24px;
  }
  .grid-overlay {
    position: fixed; inset: 0; pointer-events: none; opacity: .35;
    background-image:
      linear-gradient(rgba(255,255,255,.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,.03) 1px, transparent 1px);
    background-size: 42px 42px;
  }
  .card {
    position: relative; width: 100%; max-width: 460px; text-align: center;
    background: rgba(255,255,255,.04); border: 1px solid rgba(255,255,255,.08);
    border-radius: 20px; padding: 48px 40px 36px; backdrop-filter: blur(14px);
    box-shadow: 0 24px 80px rgba(0,0,0,.55);
  }
  h1 { margin: 0 0 10px; font-size: 24px; font-weight: 700; letter-spacing: -.01em; }
  p { margin: 0 0 24px; color: #93a4b8; font-size: 15px; line-height: 1.6; }
  .alert {
    margin: 0 0 18px; padding: 10px 14px; font-size: 13px; color: #fca5a5;
    background: rgba(248,113,113,.1); border: 1px solid rgba(248,113,113,.35); border-radius: 8px;
  }
  .widget { display: flex; justify-content: center; min-height: 78px; margin-bottom: 6px; }
  button {
    background: var(--accent); color: #04121a; border: 0; border-radius: 10px;
    padding: 12px 28px; font-size: 15px; font-weight: 700; cursor: pointer; margin-top: 18px;
    transition: transform .15s ease, box-shadow .15s ease;
  }
  button:hover { transform: translateY(-1px); box-shadow: 0 8px 24px {{ $accent }}55; }
  .footer { margin-top: 26px; font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: #46566b; }
</style>
</head>
<body>
  <div class="grid-overlay"></div>
  <div class="card">
    <h1>Verify you are human</h1>
    <p>Complete the check below to continue. Automated traffic is not allowed.</p>

    @if ($error)
      <div class="alert">Verification failed. Please try again.</div>
    @endif

    <form id="shield-form" method="post" action="/shield/challenge/verify">
      <input type="hidden" name="_token" value="{{ $csrfToken }}">
      <input type="hidden" name="redirect" value="{{ $redirect }}">
      <input type="hidden" name="shield_challenge_token" id="shield-challenge-token" value="{{ $testToken }}">

      <div class="widget">
        @if ($driver === 'recaptcha')
          <div class="g-recaptcha" data-sitekey="{{ $siteKey }}" data-callback="onChallengeSolved"></div>
          <script src="https://www.google.com/recaptcha/api.js" async defer></script>
        @elseif ($driver === 'null')
          <p style="color:#93a4b8;font-size:14px;margin:18px 0 0;">Press Verify to continue.</p>
        @else
          <div class="cf-turnstile" data-sitekey="{{ $siteKey }}" data-callback="onChallengeSolved"></div>
          <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        @endif
      </div>

      <button type="submit">Verify</button>
    </form>

    <div class="footer">{{ $title }}</div>
  </div>
  <script>
    function onChallengeSolved(token) {
      var input = document.getElementById('shield-challenge-token');
      if (token) {
        input.value = token;
      } else if (typeof grecaptcha !== 'undefined' && grecaptcha.getResponse) {
        input.value = grecaptcha.getResponse();
      }
      document.getElementById('shield-form').submit();
    }
  </script>
</body>
</html>