$path = Get-Location
Set-Location ../../WebstormProjects/mikrotik_parser

npm install
npm run build

$dest = Join-Path $path "web/dist"

if (Test-Path "./dist/") {
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null

    Copy-Item -Path "./dist/*" -Destination $dest -Recurse -Force
    Set-Location $path
} else {
    Write-Error "Copying error: ./dist not found"
    Set-Location $path
    exit 1
}
