# Pester tests for the Third-Party Application Vulnerabilities repository.
# Run with:  Invoke-Pester -Path ./tests
#
# These validate the deployable artifacts (workbook JSON, Bicep, Postman
# collection/environment) and the embedded Postman JavaScript, since the
# repository is configuration- and script-based rather than compiled code.

BeforeAll {
    $script:Repo        = Split-Path -Parent $PSScriptRoot
    $script:WorkbookPath = Join-Path $Repo 'workbook/third-party-vulnerabilities.workbook.json'
    $script:BicepPath    = Join-Path $Repo 'workbook/deploy.bicep'
    $script:CollPath     = Join-Path $Repo 'postman/third-party-vulnerabilities.postman_collection.json'
    $script:EnvPath      = Join-Path $Repo 'postman/third-party-vulnerabilities.postman_environment.json'

    $script:WorkbookRaw  = Get-Content $WorkbookPath -Raw
    $script:Workbook     = $WorkbookRaw | ConvertFrom-Json
    $script:CollRaw      = Get-Content $CollPath -Raw
    $script:Collection   = $CollRaw | ConvertFrom-Json
    $script:BicepRaw     = Get-Content $BicepPath -Raw
}

Describe 'JSON validity' {
    It 'workbook JSON parses' {
        { Get-Content $WorkbookPath -Raw | ConvertFrom-Json } | Should -Not -Throw
    }
    It 'Postman collection JSON parses' {
        { Get-Content $CollPath -Raw | ConvertFrom-Json } | Should -Not -Throw
    }
    It 'Postman environment JSON parses' {
        { Get-Content $EnvPath -Raw | ConvertFrom-Json } | Should -Not -Throw
    }
}

Describe 'Strict JSON validity' {
    # PowerShell's ConvertFrom-Json tolerates raw control characters inside
    # string literals; the JSON spec and most parsers (Node, browsers, the
    # Postman importer) do not. Validate with a strict parser so unescaped
    # newlines or tabs cannot slip into a shipped artifact.
    $jsonFiles = @(
        'workbook/third-party-vulnerabilities.workbook.json',
        'postman/third-party-vulnerabilities.postman_collection.json',
        'postman/third-party-vulnerabilities.postman_environment.json'
    )
    It "parses '<_>' under a strict JSON parser" -ForEach $jsonFiles {
        $path = Join-Path $Repo $_
        $null = node -e "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))" $path 2>$null
        $LASTEXITCODE | Should -Be 0 -Because "$_ must be valid per the JSON spec, not just PowerShell"
    }
}

Describe 'Workbook structure' {
    It 'declares the Notebook/1.0 schema version' {
        $Workbook.version | Should -Be 'Notebook/1.0'
    }
    It 'contains the expected number of items' {
        $Workbook.items.Count | Should -Be 19
    }
    It 'defines a domain parameter selector with entra and software values' {
        $WorkbookRaw | Should -Match '"name":\s*"domain"'
        $WorkbookRaw | Should -Match '"value":\s*"entra"'
        $WorkbookRaw | Should -Match '"value":\s*"software"'
    }
    It 'scopes the software filter parameters to the software domain' {
        $paramsItem = $Workbook.items |
            Where-Object { $_.type -eq 9 -and $_.conditionalVisibility.parameterName -eq 'domain' } |
            Select-Object -First 1
        $paramsItem | Should -Not -BeNullOrEmpty
        $paramsItem.conditionalVisibility.value | Should -Be 'software'
    }
    It 'colors the severity tiles by threshold (formatter 18)' {
        $tiles = $Workbook.items | Where-Object { $_.name -eq 'tiles-by-severity' } | Select-Object -First 1
        $tiles | Should -Not -BeNullOrEmpty
        $tiles.content.visualization | Should -Be 'tiles'
        $tiles.content.tileSettings.titleContent.formatter | Should -Be 18
        $reps = $tiles.content.tileSettings.titleContent.formatOptions.thresholdsGrid.representation
        $reps | Should -Contain 'redBright'
        $reps | Should -Contain 'orange'
        $reps | Should -Contain 'yellow'
        $reps | Should -Contain 'blue'
    }
    It 'pages oauth2PermissionGrants with $top' {
        $WorkbookRaw | Should -Match 'oauth2PermissionGrants\?\$top=\d+'
    }
}

Describe 'Workbook content quality' {
    $bannedWords = @(
        'attack surface',
        'over-privilege',
        'most dangerous',
        'Credential hygiene',
        'Risky delegated',
        'High-privilege Microsoft Graph',
        'remediation status'
    )
    It "does not contain overclaiming phrase '<_>'" -ForEach $bannedWords {
        $WorkbookRaw | Should -Not -Match ([regex]::Escape($_))
    }

    $expectedTitles = @(
        'Microsoft Entra recommendations',
        'Enterprise applications (service principals)',
        'Application credentials (secrets and certificates)',
        'Delegated permission grants (OAuth2)',
        'Microsoft Graph application (app-only) permissions'
    )
    It "includes the neutral grid title '<_>'" -ForEach $expectedTitles {
        $WorkbookRaw | Should -Match ('"title":\s*"' + [regex]::Escape($_) + '"')
    }
}

Describe 'Reviewer remediations' {
    It 'builds a working NVD link for CVE findings instead of a bare-id no-op' {
        $grid = $Workbook.items | Where-Object { $_.name -eq 'grid-findings' } | Select-Object -First 1
        $grid.content.query | Should -Match 'nvd\.nist\.gov/vuln/detail/'
        $fmt = $grid.content.gridSettings.formatters | Where-Object { $_.columnMatch -eq 'NVD' } | Select-Object -First 1
        $fmt.formatter | Should -Be 7
        $fmt.formatOptions.linkTarget | Should -Be 'Url'
    }
    It 'defaults the Severity filter to Critical and High, matching the dropdown selection' {
        $sev = ($Workbook.items | Where-Object { $_.name -eq 'parameters' }).content.parameters |
            Where-Object { $_.name -eq 'Severity' } | Select-Object -First 1
        ($sev.value -join ',') | Should -Be 'Critical,High'
    }
    It 'scopes the summary severity tiles to the Vendor filter' {
        $tiles = $Workbook.items | Where-Object { $_.name -eq 'tiles-by-severity' } | Select-Object -First 1
        $tiles.content.query | Should -Match 'vendor in~ \(\{Vendor\}\)'
    }
    It 'derives the finding Resource from the assessed resource id' {
        $grid = $Workbook.items | Where-Object { $_.name -eq 'grid-findings' } | Select-Object -First 1
        $grid.content.query | Should -Match 'split\(tostring\(properties\.resourceDetails\.id\)'
    }
    It 'declares the domain parameter before the software-filter block' {
        $names = @($Workbook.items.name)
        [array]::IndexOf($names, 'hidden-defaults') | Should -BeLessThan ([array]::IndexOf($names, 'parameters'))
    }
}

Describe 'Bicep template' {
    It 'compiles with az bicep build' {
        $null = az bicep build --file $BicepPath --stdout 2>$null
        $LASTEXITCODE | Should -Be 0
    }
    It 'publishes to the generic workbook gallery (not sentinel)' {
        $BicepRaw | Should -Match "category:\s*'workbook'"
        $BicepRaw | Should -Not -Match "category:\s*'sentinel'"
    }
    It 'derives workbookId from a fixed seed, not the display name' {
        $BicepRaw | Should -Match "guid\(resourceGroup\(\)\.id,\s*'third-party-vulnerabilities-workbook'\)"
        $BicepRaw | Should -Not -Match 'guid\(resourceGroup\(\)\.id,\s*workbookDisplayName\)'
    }
}

Describe 'Postman collection' {
    It 'uses bearer authentication' {
        $Collection.auth.type | Should -Be 'bearer'
    }
    It 'has a collection-level pre-request token script' {
        $pre = $Collection.event | Where-Object { $_.listen -eq 'prerequest' }
        $pre | Should -Not -BeNullOrEmpty
        ($pre.script.exec -join "`n") | Should -Match 'client_credentials'
    }
    It 'contains six requests (five Graph endpoints plus pagination)' {
        $Collection.item.Count | Should -Be 6
    }
    It 'handles throttling and asserts an array on every request' {
        foreach ($item in $Collection.item) {
            $test = $item.event | Where-Object { $_.listen -eq 'test' }
            $body = $test.script.exec -join "`n"
            $body | Should -Match '429'
            $body | Should -Match 'Array\.isArray'
        }
    }
    It 'documents that request 5 covers Microsoft Graph only' {
        $req5 = $Collection.item | Where-Object { $_.name -match 'App role assignments' } | Select-Object -First 1
        $req5.request.description | Should -Match 'Microsoft Graph only'
    }
}

Describe 'Postman JavaScript syntax' {
    BeforeAll {
        $script:Scripts = [System.Collections.Generic.List[string]]::new()
        foreach ($e in $Collection.event) {
            if ($e.script.exec) { $Scripts.Add(($e.script.exec -join "`n")) }
        }
        foreach ($item in $Collection.item) {
            foreach ($e in $item.event) {
                if ($e.script.exec) { $Scripts.Add(($e.script.exec -join "`n")) }
            }
        }
    }
    It 'has at least the collection pre-request plus six test scripts' {
        $Scripts.Count | Should -BeGreaterOrEqual 7
    }
    It 'passes node --check for every embedded script' {
        for ($i = 0; $i -lt $Scripts.Count; $i++) {
            $file = Join-Path $TestDrive ("script_$i.js")
            Set-Content -Path $file -Value $Scripts[$i] -Encoding utf8
            $null = node --check $file 2>$null
            $LASTEXITCODE | Should -Be 0 -Because "embedded script #$i should be valid JavaScript"
        }
    }
}

Describe 'Repository files' {
    It 'has a README at the repository root' {
        Test-Path (Join-Path $Repo 'README.md') | Should -BeTrue
    }
    It 'has a .gitignore' {
        Test-Path (Join-Path $Repo '.gitignore') | Should -BeTrue
    }
    It 'has a LICENSE' {
        Test-Path (Join-Path $Repo 'LICENSE') | Should -BeTrue
    }
}

Describe 'README accuracy' {
    BeforeAll {
        $script:RootReadme     = Get-Content (Join-Path $Repo 'README.md') -Raw
        $script:WorkbookReadme = Get-Content (Join-Path $Repo 'workbook/README.md') -Raw
    }

    # The five Entra tab labels as they actually appear in the workbook.
    $currentTabNames = @(
        'Entra recommendations',
        'Enterprise application inventory',
        'Application credentials',
        'Delegated permission grants',
        'Microsoft Graph app permissions'
    )
    # Earlier tab names that no longer exist in the workbook UI.
    $staleTabNames = @(
        'Remediation (Entra Recommendations)',
        'Third-Party App Inventory',
        'Credential Hygiene',
        'Risky Delegated Consents',
        'High-Privilege App Permissions',
        'Remediation tab'
    )

    It "root README documents the current tab '<_>'" -ForEach $currentTabNames {
        $RootReadme | Should -Match ([regex]::Escape($_))
    }
    It "workbook README documents the current tab '<_>'" -ForEach $currentTabNames {
        $WorkbookReadme | Should -Match ([regex]::Escape($_))
    }
    It "root README does not reference the stale tab '<_>'" -ForEach $staleTabNames {
        $RootReadme | Should -Not -Match ([regex]::Escape($_))
    }
    It "workbook README does not reference the stale tab '<_>'" -ForEach $staleTabNames {
        $WorkbookReadme | Should -Not -Match ([regex]::Escape($_))
    }

    $expectedGridTitle = @(
        'GET /beta/directory/recommendations',
        'GET /v1.0/servicePrincipals',
        'GET /v1.0/applications',
        'GET /v1.0/oauth2PermissionGrants'
    )
    It "root README lists the Graph endpoint '<_>'" -ForEach $expectedGridTitle {
        $RootReadme | Should -Match ([regex]::Escape($_))
    }
}

Describe 'Postman behavioral coverage' {
    # Executes the embedded Postman JavaScript against mocks and enforces
    # >= 80% line/branch/function coverage via the Node built-in test runner.
    It 'runs the embedded scripts at >= 80% coverage' {
        $harness = Join-Path $Repo 'tests/postman/postman.test.mjs'
        Test-Path $harness | Should -BeTrue
        Push-Location $Repo
        try {
            $null = node --test --experimental-test-coverage `
                --test-coverage-include="**/generated/**" `
                --test-coverage-lines=0.8 `
                --test-coverage-branches=0.8 `
                --test-coverage-functions=0.8 `
                $harness 2>&1
            $LASTEXITCODE | Should -Be 0 -Because 'behavioral tests must pass and meet the 80% coverage thresholds'
        }
        finally {
            Pop-Location
        }
    }
}
