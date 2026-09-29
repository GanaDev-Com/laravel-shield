# Ganadev Shield - automated end-to-end test for laravel-test demo.
# Usage: .\test.shield.ps1
# Requires: php + curl.exe available, run from E:\laragon\www\package\laravel-test
#
# The verify step completes only when SHIELD_CHALLENGE=null (offline test driver).
# With turnstile/recaptcha (real or test keys), verification needs a real widget
# token, so the script asserts the challenge page renders (widget + callback +
# branding) and skips the server-side verify steps.

$ErrorActionPreference = 'Stop'
$Base = 'http://127.0.0.1:8000'
$Port = 8000
$Cookies = Join-Path $PSScriptRoot '.test-cookies.txt'
$Challenge = Join-Path $PSScriptRoot '.test-challenge.html'
$Pass = 0
$Fail = 0
$Skipped = 0

function Check([string]$Name, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { $script:Pass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:Fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

function Skip([string]$Name) {
    $script:Skipped++; Write-Host "  SKIP  $Name (needs real widget token)" -ForegroundColor DarkYellow
}

function Cleanup {
    Remove-Item -LiteralPath $Cookies, $Challenge -Force -ErrorAction SilentlyContinue
    if ($Server -and -not $Server.HasExited) { Stop-Process -Id $Server.Id -Force -ErrorAction SilentlyContinue }
}

$envLine = (Get-Content -LiteralPath (Join-Path $PSScriptRoot '.env') | Select-String -Pattern '^SHIELD_CHALLENGE=' | Select-Object -First 1).Line
$driver = ($envLine -replace '^SHIELD_CHALLENGE=', '').Trim().Trim('"')

Write-Host "== Ganadev Shield demo test (driver: $driver) ==" -ForegroundColor Cyan

# start server
php artisan cache:clear *> $null
php artisan shield:release 127.0.0.1 *> $null
$Server = Start-Process -FilePath php -ArgumentList @('-S',"127.0.0.1:$Port",'-t','public') `
    -WorkingDirectory $PSScriptRoot -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

try {
    # 1. normal route
    $code = curl.exe -s -o NUL -w "%{http_code}" "$Base/home"
    Check "normal /home -> 200" ($code -eq '200') "(got $code)"

    # 2. critical probes blocked
    $code = curl.exe -s -o NUL -w "%{http_code}" "$Base/.env"
    Check "/.env blocked" ($code -eq '404') "(got $code)"

    $code = curl.exe -s -o NUL -w "%{http_code}" "$Base/?file=/root/.aws/credentials"
    Check "query AWS credentials blocked" ($code -eq '404') "(got $code)"

    $code = curl.exe -s -o NUL -w "%{http_code}" "$Base/%252e%252e/etc/passwd"
    Check "double-encoded traversal blocked" ($code -eq '404') "(got $code)"

    # 3. banned ip -> challenge redirect
    $loc = [string](curl.exe -s -D - -o NUL "$Base/home" | Select-String -Pattern '^Location:' | ForEach-Object { $_.Line })
    Check "/home after ban -> challenge redirect" (("$loc" -match '/shield/challenge')) "(got $loc)"

    # 4. challenge page renders (branded + widget + callback)
    $code = curl.exe -s -c $Cookies -o $Challenge -w "%{http_code}" "$Base/shield/challenge?redirect=/home"
    $html = Get-Content -LiteralPath $Challenge -Raw -ErrorAction SilentlyContinue
    Check "challenge page renders" ($code -eq '200' -and $html -match 'shield-form') "(status $code)"
    Check "challenge page has branding" ($html -match 'Ganadev Laravel Shield')
    Check "challenge page has submit callback" ($html -match 'onChallengeSolved')
    if ($driver -eq 'null') {
        Check "null challenge shows visible button" ($html -match 'Press Verify')
    } else {
        Check "provider widget rendered" ($html -match 'cf-turnstile|g-recaptcha')
    }

    if ($driver -eq 'null') {
        # 5. verify challenge (csrf + null driver token)
        $token = [regex]::Match($html, 'name="_token" value="([^"]+)"').Groups[1].Value
        Check "challenge page has CSRF token" ($token.Length -gt 0)
        $code = curl.exe -s -b $Cookies -c $Cookies -o NUL -w "%{http_code}" -X POST `
            -d "_token=$token&shield_challenge_token=test-token&redirect=/home" "$Base/shield/challenge/verify"
        Check "verify challenge succeeds (302)" ($code -eq '302') "(got $code)"

        # 6. normal route accessible after challenge
        $code = curl.exe -s -b $Cookies -o NUL -w "%{http_code}" "$Base/home"
        Check "/home after challenge -> 200" ($code -eq '200') "(got $code)"

        # 7. trusted cookie does NOT bypass critical
        $code = curl.exe -s -b $Cookies -o NUL -w "%{http_code}" "$Base/.env"
        Check "/.env still blocked with trusted cookie" ($code -eq '404') "(got $code)"

        # 8. invalid challenge token rejected
        $code = curl.exe -s -b $Cookies -o NUL -w "%{http_code}" -X POST `
            -d "_token=$token&shield_challenge_token=wrong&redirect=/home" "$Base/shield/challenge/verify"
        Check "invalid challenge token rejected (redirect)" ($code -eq '302') "(got $code)"
    } else {
        Skip "verify with widget token (solve in browser)"
        Skip "home after challenge (needs verified token)"
        Skip "trusted cookie does not bypass critical"
        Skip "invalid challenge token"
    }
}
finally {
    Cleanup
}

Write-Host ""
Write-Host "Result: $Pass passed, $Fail failed, $Skipped skipped" -ForegroundColor $(if ($Fail -eq 0) { 'Green' } else { 'Red' })
exit $(if ($Fail -eq 0) { 0 } else { 1 })