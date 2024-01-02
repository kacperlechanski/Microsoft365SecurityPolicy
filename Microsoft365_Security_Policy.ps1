#SKRYPT KONFIGURUJĄCY POLITYKI BEZPIECZEŃSTWA W MICROSOFT 365#

Write-Host "SKRYPT KONFIGURUJĄCY POLITYKI BEZPIECZEŃSTWA W MICROSOFT 365" -ForegroundColor Yellow
Start-Sleep -Seconds 3

#INSTALACJA MODUŁÓW
function Modules {
    Write-Host "Instaluje wymagane moduły Microsoft 365 dla Powershell..." -ForegroundColor Yellow
    Install-Module ExchangeOnlineManagement -Force -AllowClobber
    Install-Module MSOnline -Force -AllowClobber
}

#LOGOWANIE#
function Login {
    Write-Host "Logowanie do wymaganych modułów.." -ForegroundColor Yellow
    Connect-ExchangeOnline
    Connect-MsolService
}

#POBRANE ILOŚCI DOMEN I ICH NAZW
$domains = @()
$x = Read-Host "Ile domen posiadasz w Microsoft 365 ? Policz także domene 'onmicrosoft.com'"

for ($i = 1; $i -le $x; $i++) {
    $domain = Read-Host "Podaj nazwę domeny numer $i"
    $domains += $domain
}

Write-Host "Twoje domeny to:"


##########################################POLITYKA ANTYPHISINGOWA
function AntiPhisingPolicy {
    $antiphisingPolicyName = Read-Host "Podaj nazwę polityki ANTYPHISINGOWEJ" #podajemy nazwę polityki
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
    Write-Host "Tworzę regułę ANTYPHISINGOWĄ.." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
}


######################################################################################################################################################


##########################################POLITYKA ANTYSPAMOWA
function AntiSpamPolicy {
    $spamPolicyName = Read-Host "Podaj nazwę polityki ANTYSPAMOWEJ: " #Podajemy nazwę polityki
    New-HostedContentFilterPolicy -Name $spamPolicyName
    Write-Host "Tworzę politykę ANTYSPAMOWĄ.." -ForegroundColor Yellow
    Start-Sleep -Seconds 3

    #USTAWIENIA
    #####ZWIĘKSZ PUNKTY SPAMU
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -BulkThreshold 7
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -IncreaseScoreWithImageLinks Off
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -IncreaseScoreWithRedirectToOtherPort On
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -IncreaseScoreWithBizOrInfoUrls On
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -IncreaseScoreWithNumericIps On

    #####OZNACZ JAKO SPAM
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -MarkAsSpamEmptyMessages On
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -MarkAsSpamEmbedTagsInHtml On
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -MarkAsSpamJavaScriptInHtml On
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -MarkAsSpamFormTagsInHtml On
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -MarkAsSpamFramesInHtml On
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -MarkAsSpamObjectTagsInHtml On
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -MarkAsSpamWebBugsInHtml On
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -MarkAsSpamSensitiveWordList Off
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -MarkAsSpamSpfRecordHardFail On
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -IntraOrgFilterState HighConfidenceSpam
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -MarkAsSpamNdrBackscatter On
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -EnableLanguageBlockList $false
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -EnableRegionBlockList $false
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -TestModeAction None


    #AKCJE
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -SpamAction MoveToJmf
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -HighConfidenceSpamAction Quarantine -HighConfidenceSpamQuarantineTag AdminOnlyAccessPolicy
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -PhishSpamAction Quarantine -PhishQuarantineTag AdminOnlyAccessPolicy
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -HighConfidencePhishAction Quarantine -HighConfidencePhishQuarantineTag AdminOnlyAccessPolicy
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -QuarantineRetentionPeriod 30
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -InlineSafetyTipsEnabled $true
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -SpamZapEnabled $true
    Set-HostedContentFilterPolicy -Identity $spamPolicyName -PhishZapEnabled $true


    #REGUŁA
    $spamRuleName = Read-Host "Podaj nazwe reguły spamowej: " #Podajemy nazwę reguły
    Write-Host "Tworzę regułę ANTYSPAMOWĄ.." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    New-HostedContentFilterRule -Name $spamRuleName -HostedContentFilterPolicy $spamPolicyName -Enabled $true -Priority 0 -RecipientDomainIs $domains

}

######################################################################################################################################################

##########################################POLITYKA ANTYMALWARE

function AntiMalwarePolicy {
    Write-Host "Tworzę udostępnioną skrzynkę malware@ do powiadomień o zablokowanej zawartości w malware w plikach lub mailach.." -ForegroundColor Yellow
    New-Mailbox -Shared -Name "Malware" -DisplayName "Malware" -Alias "Malware"
    Write-Host "Blokowanie logowania skrzynki malware@.." -ForegroundColor Yellow
    Set-MsolUser -DisplayName Malware -BlockCredential $true

    $malwarePolicyName = Read-Host "Podaj nazwę polityki ANTYMALWARE: " #podajemy nazwę polityki
    New-MalwareFilterPolicy -Name $malwarePolicyName

    #USTAWIENIA
    $filesExtensions =
    "ace",
    "apk",
    "app",
    "appx",
    "ani",
    "arj",
    "bat",
    "cab",
    "cmd",
    "com",
    "deb",
    "dex",
    "dll",
    "docm",
    "elf",
    "exe",
    "hta",
    "img",
    "iso",
    "jnlp",
    "kext",
    "lha",
    "lib",
    "library",
    "lnk",
    "lzh",
    "macho",
    "msc",
    "msi",
    "msix",
    "msp",  
    "mst",
    "pif",
    "ppa",
    "ppam",
    "reg",
    "rev",
    "scf",
    "scr",
    "sct",
    "sys",
    "uif",
    "vb",
    "vbe",
    "vbs",
    "vxd",
    "wsc",
    "wsf",
    "wsh",
    "xll",
    "xz",
    "z",
    "ink",
    "swf",
    "gzquar",
    "js",
    "zix",
    "ocx",
    "bin",
    "class",
    "ws",   
    "drv",
    "ozd",
    "wmf",
    "aru",
    "shs",
    "dev",
    "chm",
    "pgm",
    "xnxx",
    "xlm",
    "tps",
    "vba",
    "pcx",
    "boo",
    "386",
    "sop",
    "dxz ",
    "hlp",
    "tsa",
    "exe1",
    "bkd",
    "rhk",
    "vbx",
    "lik",
    "osa",
    "cih",
    "mjz",
    "dlb",
    "php3",
    "dyz",
    "dom",
    "hlw",
    "s7p",
    "cla",
    "mjg",
    "mfu",
    "spam",
    "dyv",
    "kcd",
    "bup",
    "rsc_tmp",
    "mcq",
    "upa",
    "bxz",
    "xir",
    "bhx",
    "dli",
    "txs",
    "cxq",
    "fhr",
    "xdu",
    "xlv",
    "wlpginstall",
    "ska",
    "tti",
    "cfxxe",
    "dllx",
    "smtmp",
    "vexe",
    "qrn",
    "xtbl",
    "fag",
    "oar",
    "ceo",
    "tko",
    "uzy",
    "bll",
    "dbd",
    "plc",
    "smm",
    "ssy",
    "blf",
    "zvz",
    "cc",
    "ce0",
    "nls",
    "ctbl",
    "hsq",
    "crypt1",
    "iws",
    "vzr",
    "lkh",
    "ezt",
    "aepl",
    "rna",
    "hts",
    "let",
    "atm",
    "fuj",
    "aut",
    "fjl",
    "buk",
    "delf",
    "bmw",
    "capxml",
    "cyw",
    "bps",
    "iva",
    "pid",
    "lpaq5",
    "dx",
    "bqf",
    "qit",
    "pr",
    "lok",
    "xnt",
    "jar"
    Set-MalwareFilterPolicy -Identity $malwarePolicyName -EnableFileFilter $true -FileTypes $filesExtensions
    Set-MalwareFilterPolicy -Identity $malwarePolicyName -FileTypeAction Reject
    Set-MalwareFilterPolicy -Identity $malwarePolicyName -QuarantineTag AdminOnlyAccess

    $adminMail = Read-Host-Host "Podaj adres administratora do powiadomień o zainfekowanych plikach "
    Set-MalwareFilterPolicy -Identity $malwarePolicyName -EnableInternalSenderAdminNotifications $true -InternalSenderAdminAddress $adminMail
    $malwareMail = Read-Host "Podaj adres stworzonej skrzynki udostępnionej do powiadomień o malware "
    Set-MalwareFilterPolicy -Identity $malwarePolicyName -EnableExternalSenderAdminNotifications $true -ExternalSenderAdminAddress $malwareMail
    Set-MalwareFilterPolicy -Identity $malwarePolicyName -CustomNotifications $false

    #REGUŁA
    $malwareRuleName = Read-Host "Podaj nazwę reguły ANTYMALWARE: "
    New-MalwareFilterRule -Name $malwareRuleName -Priority 0 -MalwareFilterPolicy $malwarePolicyName -RecipientDomainIs $domains
}

######################################################################################################################################################

##########################################POLITYKA BEZPIECZNYCH ZAŁĄCZNIKÓW
function SafeAttachments {
    $safeAttachmentsPolicyName = Read-Host "Podaj nazwe polityki bezpiecznych załączników "
    New-SafeAttachmentPolicy -Name $safeAttachmentsPolicyName
    Write-Host "Tworzę politykę bezpiecznych załączników.." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    Set-SafeAttachmentPolicy -Identity $safeAttachmentsPolicyName -Enabled $true -Action Block -QuarantineTag AdminOnlyAccessPolicy

    $safeAttachmentRuleName = Read-Host "Podaj nazwę reguły bezpiecznych załączników "
    New-SafeAttachmentRule -Name $safeAttachmentRuleName -SafeAttachmentPolicy $safeAttachmentsPolicyName
    Write-Host "Tworzę reguły bezpiecznych załączników.." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    Set-SafeAttachmentRule -Identity $safeAttachmentRuleName -Enabled $true -Priority 0 -RecipientDomainIs $domains
}


######################################################################################################################################################

##########################################POLITYKA BEZPIECZNYCH LINKÓW

function SafeLinks {
    $safeLinksPolicyName = Read-Host "Podaj nazwę polityki bezpiecznych linków "
    New-SafeLinksPolicy -Name $safeLinksPolicyName
    Write-Host "Tworzę politykę bezpiecznych linków.." -ForegroundColor Yellow
    Start-Sleep -Seconds 3

    #USTAWIENIA
    Set-SafeLinksPolicy -Enabled $true -Identity $safeLinksPolicyName -EnableSafeLinksForEmail $true
    Set-SafeLinksPolicy -Identity $safeLinksPolicyName -EnableForInternalSenders $true
    Set-SafeLinksPolicy -Identity $safeLinksPolicyName -DeliverMessageAfterScan $true
    Set-SafeLinksPolicy -Identity $safeLinksPolicyName -EnableOrganizationBranding $false
    Set-SafeLinksPolicy -Identity $safeLinksPolicyName -CustomNotifications $false
    Set-SafeLinksPolicy -Identity $safeLinksPolicyName -AllowClickThrough $true
    Set-SafeLinksPolicy -Identity $safeLinksPolicyName -DisableUrlRewrite $true
    Set-SafeLinksPolicy -Identity $safeLinksPolicyName -DoNotRewriteUrls $true
    Set-SafeLinksPolicy -Identity $safeLinksPolicyName -EnableSafeLinksForOffice $true
    Set-SafeLinksPolicy -Identity $safeLinksPolicyName -EnableSafeLinksForTeams $true
    Set-SafeLinksPolicy -Identity $safeLinksPolicyName -ScanUrls $true
    Set-SafeLinksPolicy -Identity $safeLinksPolicyName -TrackClicks $true


    $safeLinksRuleName = Read-Host "Podaj nazwę reguły bezpiecznych linków "
    New-SafeLinksRule -Identity $safeLinksRuleName -SafeLinksPolicy $safeLinksPolicyName
    Write-Host "Tworzę regułe bezpiecznych linków.." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    Set-SafeLinksRule -Identity $safeLinksRuleName -Enabled $true -Priority 0 -RecipientDomainIs $domains
}

#Modules
#Login
#AntiPhisingPolicy
#AntiSpamPolicy
#AntiMalwarePolicy
#SafeAttachments
#SafeLinks