# Build the Tatar Relay Burp extension jar WITHOUT Gradle.
# Requires a JDK (javac + jar). Downloads Montoya API + Gson on first run.
#
#   powershell -ExecutionPolicy Bypass -File build.ps1
#
# Output: build\libs\tatar-relay-burp.jar  (load this in Burp -> Extensions -> Add -> Java)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$MONTOYA = "2023.12.1"
$GSON = "2.10.1"

# --- locate the JDK's jar.exe (javapath often lacks it) ---
$javac = (Get-Command javac -ErrorAction SilentlyContinue).Source
if (-not $javac) { throw "javac not found. Install a JDK 17+ and put it on PATH." }
$jar = $null
$cand = @()
foreach ($r in @("C:\Program Files\Java","C:\Program Files\Eclipse Adoptium","C:\Program Files\Microsoft","C:\Program Files\Amazon Corretto","C:\Program Files\Zulu")) {
    if (Test-Path $r) { $cand += Get-ChildItem $r -Recurse -Filter jar.exe -ErrorAction SilentlyContinue }
}
if ($cand.Count -gt 0) { $jar = ($cand | Sort-Object FullName -Descending | Select-Object -First 1).FullName }
if (-not $jar) { $jar = (Get-Command jar -ErrorAction SilentlyContinue).Source }
if (-not $jar) { throw "jar.exe not found in any JDK under Program Files." }
Write-Host "javac: $javac"
Write-Host "jar  : $jar"

# --- deps ---
New-Item -ItemType Directory -Force -Path lib,out,build\libs | Out-Null
if (-not (Test-Path lib\montoya-api.jar)) {
    Invoke-WebRequest "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/$MONTOYA/montoya-api-$MONTOYA.jar" -OutFile lib\montoya-api.jar -UseBasicParsing
}
if (-not (Test-Path lib\gson.jar)) {
    Invoke-WebRequest "https://repo1.maven.org/maven2/com/google/code/gson/gson/$GSON/gson-$GSON.jar" -OutFile lib\gson.jar -UseBasicParsing
}

# --- compile (Java 17 bytecode for Burp's JRE) ---
Remove-Item -Recurse -Force out\* -ErrorAction SilentlyContinue
$src = (Get-ChildItem -Recurse src\main\java\relay\*.java).FullName
& $javac --release 17 -cp "lib\montoya-api.jar;lib\gson.jar" -d out $src
if ($LASTEXITCODE -ne 0) { throw "javac failed" }

# --- bundle gson into the fat jar ---
Push-Location out
& $jar xf ..\lib\gson.jar
Pop-Location
Remove-Item -Recurse -Force out\META-INF -ErrorAction SilentlyContinue
Remove-Item -Force out\module-info.class -ErrorAction SilentlyContinue

# --- package ---
Remove-Item -Force build\libs\tatar-relay-burp.jar -ErrorAction SilentlyContinue
& $jar cf build\libs\tatar-relay-burp.jar -C out .
if ($LASTEXITCODE -ne 0) { throw "jar packaging failed" }

Write-Host ("OK -> build\libs\tatar-relay-burp.jar  ({0} KB)" -f [math]::Round((Get-Item build\libs\tatar-relay-burp.jar).Length/1kb))
Write-Host "Load it in Burp: Extensions -> Add -> Extension type: Java -> select the jar."
