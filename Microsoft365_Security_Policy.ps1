#SKRYPT KONFIGURUJĄCY POLITYKI BEZPIECZEŃSTWA W MICROSOFT 365#

Write-Host "SKRYPT KONFIGURUJĄCY POLITYKI BEZPIECZEŃSTWA W MICROSOFT 365" -ForegroundColor Yellow
Start-Sleep -Seconds 3

function Login {
    Connect-ExchangeOnline
}

function GetDomains{
    $domains = @()
    $x = Read-Host "Ile domen posiadasz w Microsoft 365 ? Policz także domene 'onmicrosoft.com'"

    for($i = 1; $i -le $x; $i++){
        $domain = Read-Host "Podaj nazwę domeny numer $i"
        $domains += $domain
    }

    Write-Host "Twoje domeny to: $($domains -join ', ')"
}

#Login
GetDomains