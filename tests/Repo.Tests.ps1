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
