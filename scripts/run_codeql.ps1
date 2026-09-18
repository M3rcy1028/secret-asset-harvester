param(
    [string]$SourceRoot = "cases",
    [string]$OutputRoot = "outputs/codeql"
)

$projectRoot = Split-Path -Parent $PSScriptRoot
$codeql = Join-Path $projectRoot ".tools/codeql/codeql.exe"
$packRoot = Join-Path $projectRoot ".tools/codeql-python"
$database = Join-Path $projectRoot "$OutputRoot/database"
$results = Join-Path $projectRoot "$OutputRoot/secret-asset-flow.sarif"
$queries = Join-Path $projectRoot "codeql/queries"

New-Item -ItemType Directory -Path (Join-Path $projectRoot $OutputRoot) -Force | Out-Null

if (-not (Test-Path $codeql)) {
    throw "CodeQL CLI not found at $codeql. Run the documented setup first."
}

& $codeql database create $database --language=python --source-root (Join-Path $projectRoot $SourceRoot) --overwrite
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $codeql database analyze $database $queries --format=sarifv2.1.0 --output=$results --additional-packs=$packRoot
exit $LASTEXITCODE
