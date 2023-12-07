#SKRYPT KONFIGURUJĄCY POLITYKI BEZPIECZEŃSTWA W MICROSOFT 365#

Write-Host "SKRYPT KONFIGURUJĄCY POLITYKI BEZPIECZEŃSTWA W MICROSOFT 365" -ForegroundColor Yellow
Start-Sleep -Seconds 3

#LOGOWANIE#
function Login {
    Connect-ExchangeOnline
}

#POBRANE ILOŚCI DOMEN I ICH NAZW
$domains = @()
$x = Read-Host "Ile domen posiadasz w Microsoft 365 ? Policz także domene 'onmicrosoft.com'"

for($i = 1; $i -le $x; $i++){
    $domain = Read-Host "Podaj nazwę domeny numer $i"
    $domains += $domain
}

Write-Host "Twoje domeny to:"


########POLITYKA ANTYPHISINGOWA########
function AntiPhisingPolicy {
$antiphisingPolicyName= Read-Host "Podaj nazwę polityki ANTYPHISINGOWEJ" #podajemy nazwę polityki
New-AntiPhishPolicy -Name $antiphisingPolicyName

Write-Host "Tworzę politykę ANTYPHISINGOWĄ.." -ForegroundColor Yellow
Start-Sleep -Seconds 3

#USTAWIENIA
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -PhishThresholdLevel 2
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -EnableOrganizationDomainsProtection $true
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -EnableSpoofIntelligence $true
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -EnableMailboxIntelligence $true
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -EnableMailboxIntelligenceProtection $true
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -EnableFirstContactSafetyTips $true
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -EnableSimilarDomainsSafetyTips $true
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -EnableSimilarUsersSafetyTips $true
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -EnableUnusualCharactersSafetyTips $true
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -EnableViaTag $true
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -HonorDmarcPolicy $true

#AKCJE
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -MailboxIntelligenceProtectionAction MoveToJmf
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -TargetedDomainProtectionAction MoveToJmf
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -TargetedUserProtectionAction MoveToJmf
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -AuthenticationFailAction MoveToJmf
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -DmarcQuarantineAction Quarantine
Set-AntiPhishPolicy -Identity $antiphisingPolicyName -DmarcRejectAction Reject

#REGUŁA
#Tutaj powinno być tyle domen ile jest w tenancie (uwzględniająć onmicrosoft.com)
$phisingRuleName = Read-Host "Podaj nazwę reguły ANTYPHISINGOWEJ" #Podajemy nazwę reguły
New-AntiphishRule -Name $phisingRuleName -AntiPhishPolicy $antiphisingPolicyName -Enabled $true -Priority 0 -RecipientDomainIs $domains
}


#Login
AntiPhisingPolicy