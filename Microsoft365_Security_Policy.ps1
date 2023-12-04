#SKRYPT KONFIGURUJĄCY POLITYKI BEZPIECZEŃSTWA W MICROSOFT 365#

Write-Host "SKRYPT KONFIGURUJĄCY POLITYKI BEZPIECZEŃSTWA W MICROSOFT 365" -ForegroundColor Yellow
Start-Sleep -Seconds 3

#LOGOWANIE#
function Login {
    Connect-ExchangeOnline
}

#POBRANE ILOŚCI DOMEN I ICH NAZW
function GetDomains{
    $domains = @()
    $x = Read-Host "Ile domen posiadasz w Microsoft 365 ? Policz także domene 'onmicrosoft.com'"

    for($i = 1; $i -le $x; $i++){
        $domain = Read-Host "Podaj nazwę domeny numer $i"
        $domains += $domain
    }

    Write-Host "Twoje domeny to: $($domains -join ', ')"

    return $domains
}

########POLITYKA ANTYPHISINGOWA########
function AntiPhisingPolicy {
Write-Host "Tworzę politykę ANTYPHISINGOWĄ.." -ForegroundColor Yellow
Start-Sleep -Seconds 3

$antiphisingPolicyName = Read-Host "Podaj nazwę polityki ANTYPHISINGOWEJ" #podajemy nazwę polityki
New-AntiPhishPolicy -Name $antiphisingPolicyName

#USTAWIENIA

}


Login
#GetDomains
#AntiPhisingPolicy