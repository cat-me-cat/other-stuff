sal n Out-Null
sal wh Write-Host
sal ww Write-Warning
sal we Write-Error
$ProgressPreference = 'SilentlyContinue'
wh "Setting dark mode"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0
$wallpaperPath = "C:\Windows\Web\Wallpaper\Windows\img19.jpg"
$code = @'
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
'@
Add-Type $code
$SPI_SETDESKWALLPAPER = 0x0014
$UPDATE_INI_FILE = 0x01
$SEND_CHANGE = 0x02
[Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $wallpaperPath, ($UPDATE_INI_FILE -bor $SEND_CHANGE)) | n
wh "Adding context menu options"
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve | n
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f | n
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f | n
reg add HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy /v VerifiedAndReputablePolicyState /t REG_DWORD /d 0 /f | n
CiTool.exe --refresh --json | n
$editPath = "C:\Windows\System32\edit.exe"
reg add "HKEY_CLASSES_ROOT\*\shell\Edit" /f | n
reg add "HKEY_CLASSES_ROOT\*\shell\Edit" /v "Icon" /t REG_SZ /d "$editPath,0" /f | n
reg add "HKEY_CLASSES_ROOT\*\shell\Edit\command" /ve /d "`"$editPath`" `"%1`"" /f | n
cmd /c assoc .txt=txtfile | n
If (!(Test-Path 'HKLM:\SOFTWARE\Classes\txtfile\shell\open\command')) { New-Item -Path 'HKLM:\SOFTWARE\Classes\txtfile\shell\open\command' -Force | n }
cmd /c ftype txtfile=`"$editPath`" "%1" | n
reg add "HKEY_CLASSES_ROOT\.txt\ShellNew" /f | n
reg --% add "HKEY_CLASSES_ROOT\.txt\ShellNew" /v "NullFile" /t REG_SZ /d "" /f | n
reg add "HKEY_CLASSES_ROOT\.txt\ShellNew" /v "ItemName" /t REG_SZ /d "New Text Document" /f | n
$urls = @(
    "https://aka.ms/vs/17/release/vc_redist.x86.exe",
    "https://aka.ms/vs/17/release/vc_redist.x64.exe",
    "https://aka.ms/vs/17/release/vc_redist.arm64.exe"
)
$downloadPath = "$env:TEMP"
foreach ($url in $urls) {
    $fileName = $url.Split('/')[-1]
    $filePath = Join-Path $downloadPath $fileName
    wh "Downloading $fileName..."
    Invoke-WebRequest -Uri $url -OutFile $filePath
    if (Test-Path $filePath) {
        wh "Installing $fileName..."
        Start-Process -FilePath $filePath -ArgumentList "/install /quiet /norestart" -Wait
        wh "$fileName has been installed."
    } else {
        we "Failed to download $fileName."
    }
}
$flightRing = "Retail"
$flightingBranchName = ""
$currentBranch = "ge_release"
$userDownloadsFolder = (New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path
$subfolderName = "MSStore Install"
$storeCategoryId = "64293252-5926-453c-9494-2d4021f1c78d" 
$workingDir = Join-Path -Path $userDownloadsFolder -ChildPath $subfolderName
if (-not (Test-Path -Path $workingDir)) {
    New-Item -Path $workingDir -ItemType Directory -Force | n
}
$cookieXmlTemplate = @"
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie</a:Action>
        <a:MessageID>urn:uuid:$(New-Guid)</a:MessageID>
        <a:To s:mustUnderstand="1">https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization">
                <TicketType Name="MSA" Version="1.0" Policy="MBI_SSL"><user></user></TicketType>
            </wuws:WindowsUpdateTicketsToken>
        </o:Security>
    </s:Header>
    <s:Body><GetCookie xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService" /></s:Body>
</s:Envelope>
"@
$fileListXmlTemplate = @"
<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates</a:Action>
        <a:MessageID>urn:uuid:$(New-Guid)</a:MessageID>
        <a:To s:mustUnderstand="1">https://fe3cr.delivery.mp.microsoft.com/ClientWebService/client.asmx</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <Created>$((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"))</Created>
                <Expires>$((Get-Date).AddMinutes(5).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"))</Expires>
            </Timestamp>
            <wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization">
                <TicketType Name="MSA" Version="1.0" Policy="MBI_SSL">
                    <user/>
                </TicketType>
            </wuws:WindowsUpdateTicketsToken>
        </o:Security>
    </s:Header>
    <s:Body>
        <SyncUpdates xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
            <cookie>
                <Expiration>$((Get-Date).AddYears(10).ToUniversalTime().ToString('u').Replace(' ','T'))</Expiration>
                <EncryptedData>{0}</EncryptedData>
            </cookie>
            <parameters>
                <ExpressQuery>false</ExpressQuery>
                <InstalledNonLeafUpdateIDs>
                    <int>1</int><int>2</int><int>3</int><int>11</int><int>19</int><int>2359974</int><int>5169044</int>
                    <int>8788830</int><int>23110993</int><int>23110994</int><int>54341900</int><int>59830006</int><int>59830007</int>
                    <int>59830008</int><int>60484010</int><int>62450018</int><int>62450019</int><int>62450020</int><int>98959022</int>
                    <int>98959023</int><int>98959024</int><int>98959025</int><int>98959026</int><int>104433538</int><int>129905029</int>
                    <int>130040031</int><int>132387090</int><int>132393049</int><int>133399034</int><int>138537048</int><int>140377312</int>
                    <int>143747671</int><int>158941041</int><int>158941042</int><int>158941043</int><int>158941044</int><int>159123858</int>
                    <int>159130928</int><int>164836897</int><int>164847386</int><int>164848327</int><int>164852241</int><int>164852246</int>
                    <int>164852253</int>
                </InstalledNonLeafUpdateIDs>
                <SkipSoftwareSync>false</SkipSoftwareSync>
                <NeedTwoGroupOutOfScopeUpdates>false</NeedTwoGroupOutOfScopeUpdates>
                <FilterAppCategoryIds>
                    <CategoryIdentifier>
                        <Id>{1}</Id>
                    </CategoryIdentifier>
                </FilterAppCategoryIds>
                <TreatAppCategoryIdsAsInstalled>true</TreatAppCategoryIdsAsInstalled>
                <AlsoPerformRegularSync>false</AlsoPerformRegularSync>
                <ComputerSpec/>
                <ExtendedUpdateInfoParameters>
                    <XmlUpdateFragmentTypes>
                        <XmlUpdateFragmentType>Extended</XmlUpdateFragmentType>
                    </XmlUpdateFragmentTypes>
                    <Locales>
                        <string>en-US</string>
                        <string>en</string>
                    </Locales>
                </ExtendedUpdateInfoParameters>
                <ClientPreferredLanguages>
                    <string>en-US</string>
                </ClientPreferredLanguages>
                <ProductsParameters>
                    <SyncCurrentVersionOnly>false</SyncCurrentVersionOnly>
                    <DeviceAttributes>E:BranchReadinessLevel=CB&amp;CurrentBranch={2}&amp;OEMModel=Virtual%20Machine&amp;FlightRing={3}&amp;AttrDataVer=321&amp;InstallLanguage=en-US&amp;OSUILocale=en-US&amp;InstallationType=Client&amp;FlightingBranchName={4}&amp;OSSkuId=48&amp;App=WU_STORE&amp;ProcessorManufacturer=GenuineIntel&amp;OEMName_Uncleaned=Microsoft%20Corporation&amp;AppVer=1407.2503.28012.0&amp;OSArchitecture=AMD64&amp;IsFlightingEnabled=1&amp;TelemetryLevel=1&amp;DefaultUserRegion=39070&amp;WuClientVer=1310.2503.26012.0&amp;OSVersion=10.0.26100.3915&amp;DeviceFamily=Windows.Desktop</DeviceAttributes>
                    <CallerAttributes>Interactive=1;IsSeeker=1;</CallerAttributes>
                    <Products/>
                </ProductsParameters>
            </parameters>
        </SyncUpdates>
    </s:Body>
</s:Envelope>
"@
$fileUrlXmlTemplate = @"
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo2</a:Action>
        <a:MessageID>urn:uuid:$(New-Guid)</a:MessageID>
        <a:To s:mustUnderstand="1">https://fe3cr.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <u:Timestamp u:Id="_0" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <u:Created>$((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"))</u:Created>
                <u:Expires>$((Get-Date).AddMinutes(5).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"))</u:Expires>
            </u:Timestamp>
            <wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization">
                <TicketType Name="MSA" Version="1.0" Policy="MBI_SSL"><user>{0}</user></TicketType>
            </wuws:WindowsUpdateTicketsToken>
        </o:Security>
    </s:Header>
    <s:Body>
        <GetExtendedUpdateInfo2 xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
            <updateIDs><UpdateIdentity><UpdateID>{1}</UpdateID><RevisionNumber>{2}</RevisionNumber></UpdateIdentity></updateIDs>
            <infoTypes><XmlUpdateFragmentType>FileUrl</XmlUpdateFragmentType></infoTypes>
            <DeviceAttributes>E:BranchReadinessLevel=CB&amp;CurrentBranch={3}&amp;OEMModel=Virtual%20Machine&amp;FlightRing={4}&amp;AttrDataVer=321&amp;InstallLanguage=en-US&amp;OSUILocale=en-US&amp;InstallationType=Client&amp;FlightingBranchName={5}&amp;OSSkuId=48&amp;App=WU_STORE&amp;ProcessorManufacturer=GenuineIntel&amp;OEMName_Uncleaned=Microsoft%20Corporation&amp;AppVer=1407.2503.28012.0&amp;OSArchitecture=AMD64&amp;IsFlightingEnabled=1&amp;TelemetryLevel=1&amp;DefaultUserRegion=39070&amp;WuClientVer=1310.2503.26012.0&amp;OSVersion=10.0.26100.3915&amp;DeviceFamily=Windows.Desktop</DeviceAttributes>
        </GetExtendedUpdateInfo2>
    </s:Body>
</s:Envelope>
"@
$headers = @{ "Content-Type" = "application/soap+xml; charset=utf-8" }
$baseUri = "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx"
try {
    wh "Step 1: Getting authentication cookie..."
    $cookieRequestPayload = $cookieXmlTemplate
    $cookieResponse = Invoke-WebRequest -Uri $baseUri -Method Post -Body $cookieRequestPayload -Headers $headers -UseBasicParsing
    $cookieResponseXml = [xml]$cookieResponse.Content
    $encryptedCookieData = $cookieResponseXml.Envelope.Body.GetCookieResponse.GetCookieResult.EncryptedData
    wh "Success. Cookie received." -ForegroundColor Green
    wh "Step 2: Getting file list..."
    $fileListRequestPayload = $fileListXmlTemplate -f $encryptedCookieData, $storeCategoryId, $currentBranch, $flightRing, $flightingBranchName
    $fileListResponse = Invoke-WebRequest -Uri $baseUri -Method Post -Body $fileListRequestPayload -Headers $headers -UseBasicParsing
    Add-Type -AssemblyName System.Web
    $decodedContent = [System.Web.HttpUtility]::HtmlDecode($fileListResponse.Content)
    $fileListResponseXml = [xml]$decodedContent
    wh "Successfully received and DECODED Step 2 response." -ForegroundColor Green
    $fileIdentityMap = @{}
    $newUpdates = $fileListResponseXml.Envelope.Body.SyncUpdatesResponse.SyncUpdatesResult.NewUpdates.UpdateInfo
    $allExtendedUpdates = $fileListResponseXml.Envelope.Body.SyncUpdatesResponse.SyncUpdatesResult.ExtendedUpdateInfo.Updates.Update
    wh "--- Correlating Update Information ---" -ForegroundColor Magenta
    $downloadableUpdates = $newUpdates | Where-Object { $_.Xml.Properties.SecuredFragment }
    wh "Found $($downloadableUpdates.Count) potentially downloadable packages." -ForegroundColor Cyan
    foreach ($update in $downloadableUpdates) {
        $lookupId = $update.ID
        $extendedInfo = $allExtendedUpdates | Where-Object { $_.ID -eq $lookupId } | Select-Object -First 1
        if (-not $extendedInfo) {
            ww "Could not find matching ExtendedInfo for downloadable update ID $lookupId. Skipping."
            continue
        }
        $fileNode = $extendedInfo.Xml.Files.File | Where-Object { $_.FileName -and $_.FileName -notlike "Abm_*" } | Select-Object -First 1
        if (-not $fileNode) {
            ww "Found matching ExtendedInfo for ID $lookupId, but it contains no valid file node. Skipping."
            continue
        }
        $fileName = $fileNode.FileName
        $updateGuid = $update.Xml.UpdateIdentity.UpdateID
        $revNum = $update.Xml.UpdateIdentity.RevisionNumber
        $fullIdentifier = $fileNode.GetAttribute("InstallerSpecificIdentifier")
        $regex = "^(?<Name>.+?)_(?<Version>\d+\.\d+\.\d+\.\d+)_(?<Architecture>[a-zA-Z0-9]+)_(?<ResourceId>.*?)_(?<PublisherId>[a-hjkmnp-tv-z0-9]{13})$"
        $packageInfo = [PSCustomObject]@{
            FullName       = $fullIdentifier
            FileName       = $fileName
            UpdateID       = $updateGuid
            RevisionNumber = $revNum
        }
        if ($fullIdentifier -match $regex) {
            $packageInfo | Add-Member -MemberType NoteProperty -Name "PackageName" -Value $matches.Name
            $packageInfo | Add-Member -MemberType NoteProperty -Name "Version" -Value $matches.Version
            $packageInfo | Add-Member -MemberType NoteProperty -Name "Architecture" -Value $matches.Architecture
            $packageInfo | Add-Member -MemberType NoteProperty -Name "ResourceId" -Value $matches.ResourceId
            $packageInfo | Add-Member -MemberType NoteProperty -Name "PublisherId" -Value $matches.PublisherId
        } else {
            $packageInfo | Add-Member -MemberType NoteProperty -Name "PackageName" -Value "Unknown (Parsing Failed)"
            $packageInfo | Add-Member -MemberType NoteProperty -Name "Architecture" -Value "unknown"
        }
        $fileIdentityMap[$fullIdentifier] = $packageInfo
        wh "  -> CORRELATED: '$($packageInfo.PackageName)' ($($packageInfo.Architecture))" -ForegroundColor Green
    }
    wh "--- Correlation Complete ---" -ForegroundColor Magenta
    wh "Found and prepared $($fileIdentityMap.Count) downloadable files." -ForegroundColor Green
    try {
        $systemArch = switch ($env:PROCESSOR_ARCHITECTURE) {
            "AMD64" { "x64" }
            "ARM64" { "arm64" }
            "x86"   { "x86" }
            default { "unknown" }
        }
        if ($systemArch -eq "unknown") {
            throw "Could not determine system architecture from '$($env:PROCESSOR_ARCHITECTURE)'."
        }
        wh "Step 3: Filtering packages for your system architecture ('$systemArch')..." -ForegroundColor Magenta
        $latestStorePackage = $fileIdentityMap.Values |
            Where-Object { $_.PackageName -eq 'Microsoft.WindowsStore' } |
            Sort-Object { [version]$_.Version } -Descending |
            Select-Object -First 1
        $filteredDependencies = $fileIdentityMap.Values |
            Where-Object {
                ($_.PackageName -ne 'Microsoft.WindowsStore') -and
                ( ($_.Architecture -eq $systemArch) -or ($_.Architecture -eq 'neutral') )
            }
        $packagesToDownload = @()
        if ($latestStorePackage) {
            $packagesToDownload += $latestStorePackage
            wh "  -> Found latest Store package: $($latestStorePackage.FullName)" -ForegroundColor Green
        } else {
            ww "Could not find any Microsoft.WindowsStore package."
        }
        $packagesToDownload += $filteredDependencies
        wh "  -> Found $($filteredDependencies.Count) dependencies for '$systemArch' architecture." -ForegroundColor Green
        wh "Total files to download: $($packagesToDownload.Count)" -ForegroundColor Cyan
        wh "------------------------------------------------------------"
        wh "Step 4: Fetching URLs and downloading files..." -ForegroundColor Magenta
        foreach ($package in $packagesToDownload) {
            wh "Processing: $($package.FullName)"
            $fileUrlRequestPayload = $fileUrlXmlTemplate -f $encryptedCookieData, $package.UpdateID, $package.RevisionNumber, $currentBranch, $flightRing, $flightingBranchName
            $fileUrlResponse = Invoke-WebRequest -Uri "$baseUri/secured" -Method Post -Body $fileUrlRequestPayload -Headers $headers -UseBasicParsing
            $fileUrlResponseXml = [xml]$fileUrlResponse.Content
            $fileLocations = $fileUrlResponseXml.Envelope.Body.GetExtendedUpdateInfo2Response.GetExtendedUpdateInfo2Result.FileLocations.FileLocation
            $baseFileName = [System.IO.Path]::GetFileNameWithoutExtension($package.FileName)
            $downloadUrl = ($fileLocations | Where-Object { $_.Url -like "*$baseFileName*" }).Url
            if (-not $downloadUrl) {
                ww "  -> Could not retrieve download URL for $($package.FileName). Skipping."
                continue
            }
            if ($noDownload) {
                wh "  -> Skipping download for $($package.FullName) because of -noDownload switch." -ForegroundColor Yellow
                continue
            }
            $fileExtension = [System.IO.Path]::GetExtension($package.FileName)
            $newFileName = "$($package.FullName)$($fileExtension)"
            $filePath = Join-Path $workingDir $newFileName
            wh "  -> Downloading from: $downloadUrl" -ForegroundColor Gray
            wh "  -> Saving to: $filePath"
            try {
                Invoke-WebRequest -Uri $downloadUrl -OutFile $filePath -UseBasicParsing
                wh "  -> SUCCESS: Download complete." -ForegroundColor Green
            } catch {
                we "  -> FAILED to download $($newFileName). Error: $($_.Exception.Message)"
            }
            wh ""
        }
        wh "------------------------------------------------------------"
        wh "Finished downloading packages to: $workingDir" -ForegroundColor Green
    } catch {
        wh "An error occurred during the filtering or downloading phase:" -ForegroundColor Red
        wh $_.Exception.ToString()
    }
    wh "------------------------------------------------------------"
    wh "Step 5: Installing packages..." -ForegroundColor Magenta
    $dependencyInstallOrder = @(
        'Microsoft.VCLibs',
        'Microsoft.NET.Native.Framework',
        'Microsoft.NET.Native.Runtime',
        'Microsoft.UI.Xaml'
    )
    try {
        $allDownloadedFiles = Get-ChildItem -Path $workingDir -File | Where-Object { $_.Extension -in '.appx', '.msix', '.appxbundle', '.msixbundle' }
        $storePackageFile = $allDownloadedFiles | Where-Object { $_.Name -like 'Microsoft.WindowsStore*' } | Select-Object -First 1
        $dependencyFiles = $allDownloadedFiles | Where-Object { $_.Name -notlike 'Microsoft.WindowsStore*' }
        if (-not $dependencyFiles -and -not $storePackageFile) {
            ww "No package files found in '$workingDir' to install."
            return
        }
        wh "Installing dependencies..."
        foreach ($baseName in $dependencyInstallOrder) {
            $packagesInGroup = $dependencyFiles | Where-Object { $_.Name -like "$baseName*" } | Sort-Object Name
            foreach ($package in $packagesInGroup) {
                wh "  -> Installing $($package.Name)"
                try {
                    Add-AppxPackage -Path $package.FullName
                    wh "     SUCCESS." -ForegroundColor Green
                } catch {
                    we "     FAILED to install $($package.Name). Error: $($_.Exception.Message)"
                }
            }
        }
        if ($storePackageFile) {
            wh "Installing the main application..."
            wh "  -> Installing $($storePackageFile.Name)"
            try {
                Add-AppxPackage -Path $storePackageFile.FullName
                wh "     SUCCESS: Microsoft Store has been installed/updated." -ForegroundColor Green
            } catch {
                we "     FAILED to install $($storePackageFile.Name). Error: $($_.Exception.Message)"
            }
        } else {
            ww "Microsoft Store package was not found in the download folder."
        }
        wh "------------------------------------------------------------"
        wh "Installation process finished." -ForegroundColor Cyan
    } catch {
        we "A critical error occurred during the installation phase: $($_.Exception.Message)"
    }
    try {
        $geoKeyPath = "HKCU:\Control Panel\International\Geo"
        if (-not (Test-Path $geoKeyPath)) {
            wh "  -> Registry key not found. Creating: $geoKeyPath"
            New-Item -Path $geoKeyPath -Force | n
        }
        Set-ItemProperty -Path $geoKeyPath -Name "Nation" -Value "244"
        wh "  -> Set 'Nation' value to '244'."
        Set-ItemProperty -Path $geoKeyPath -Name "Name" -Value "US"
        wh "  -> Set 'Name' value to 'US'."
        wh "  -> Registry configuration complete." -ForegroundColor Green
    }
    catch {
        we "FAILED to configure registry settings. Error: $($_.Exception.Message)"
    }
} catch {
    wh "An error occurred:" -ForegroundColor Red
    if ($_.Exception.Response) {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $statusDescription = $_.Exception.Response.StatusDescription
        $errorLogPath = Join-Path $LogDirectory "ERROR_Response.txt"
        try {
            $stream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
        } catch { "Could not read error response body." | Set-Content -Path $errorLogPath }
        wh "Status Code: $statusCode"
        wh "Status Description: $statusDescription"
        wh "Server Response saved to '$errorLogPath'"
    } else {
        wh $_.Exception.ToString()
    }
}
kill -Name explorer -Force

