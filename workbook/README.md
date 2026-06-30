# Third-Party Application Vulnerabilities Workbook

> ## ⚠️ Disclaimer
>
> **This repository and its contents are provided for reference purposes only.** Any use of this
> repository and its contents is the **sole responsibility of the individual or organization using it**.
> The code is provided **as-is** and **where-is**, without warranty of any kind, express or implied,
> including but not limited to warranties of merchantability, fitness for a particular purpose, and
> non-infringement. The authors and contributors accept **no liability** for any loss, damage, or claim
> arising from the use of this repository.

An Azure Monitor workbook with two domains, selected from a top-level domain selector:

1. **Entra ID Applications** — app registrations and enterprise applications, queried through Microsoft
   Graph.
2. **Software Vulnerabilities (Defender)** — software CVEs reported by Microsoft Defender Vulnerability
   Management (MDVM), queried through Azure Resource Graph.

## Repository contents

| File | Purpose |
| --- | --- |
| `third-party-vulnerabilities.workbook.json` | The workbook definition. |
| `deploy.bicep` | Deploys the workbook from the JSON file. |
| `README.md` | This guide. |
| `../postman/third-party-vulnerabilities.postman_collection.json` | Postman collection that calls the same Microsoft Graph endpoints as the Entra ID tabs. |
| `../postman/third-party-vulnerabilities.postman_environment.json` | Postman environment template for the collection. |
| `../tests/Repo.Tests.ps1` | Pester unit tests for the workbook, Bicep, and Postman artifacts. |

## Prerequisites

- Azure subscription with the Azure CLI installed and signed in (`az login`).
- For the Entra ID domain: the signed-in user has Microsoft Graph delegated read access. The **Global
  Reader** or **Security Reader** directory role covers all five tabs. Equivalent granular scopes:
  `DirectoryRecommendations.Read.All`, `Application.Read.All`, `Directory.Read.All`,
  `DelegatedPermissionGrant.Read.All`.
- The Entra recommendations tab returns data only when Microsoft Entra ID P1 or P2 is licensed.
- For the Software domain: Microsoft Defender for Servers Plan 2 or Defender Vulnerability Management is
  enabled on the resources, and the user has the **Reader** role on the selected subscriptions.
- To save or deploy the workbook: **Monitoring Contributor** or **Workbook Contributor** on the target
  resource group.

## Step 1 — Deploy the workbook

### Option A: Bicep

```powershell
az group create --name rg-security-workbooks --location westeurope

az deployment group create `
  --resource-group rg-security-workbooks `
  --template-file deploy.bicep
```

The deployment outputs `workbookResourceId` and `workbookName`.

### Option B: Import in the portal

1. Azure Portal → **Monitor** → **Workbooks** → **+ New** → **Advanced Editor** (`</>`).
2. Paste the contents of `third-party-vulnerabilities.workbook.json`.
3. **Apply** → **Done Editing** → **Save**.

## Step 2 — Open the workbook

Azure Portal → **Monitor** → **Workbooks** → open **Third-Party Application Vulnerabilities (Entra ID +
Defender)**.

## Step 3 — Select a domain

Use the domain selector at the top to switch between **Entra ID Applications** and **Software
Vulnerabilities (Defender)**.

## Step 4 — Entra ID Applications

Select a tab. Each tab runs a Microsoft Graph query and renders the result as a table.

| Tab | Graph endpoint | Columns |
| --- | --- | --- |
| **Entra recommendations** | `GET /beta/directory/recommendations` | Recommendation, Priority, Status, Type, Impact, FlaggedSince, ActionSteps. |
| **Enterprise application inventory** | `GET /v1.0/servicePrincipals` | Application, AppId, Publisher, VerifiedPublisher, OwnerTenant, Audience, Enabled, Homepage. |
| **Application credentials** | `GET /v1.0/applications` | Application, AppId, Audience, ClientSecrets, SecretExpiry, CertExpiry, Created. |
| **Delegated permission grants** | `GET /v1.0/oauth2PermissionGrants` | ClientSP, ConsentType, User, ResourceSP, Scopes. |
| **Microsoft Graph app permissions** | `GET /v1.0/servicePrincipals(appId='00000003-…')/appRoleAssignedTo` | Application, AppSP, AppRoleId, Granted, Resource. |

Column rendering:

- **Entra recommendations**: `Status` values are `active`, `completedBySystem`, `completedByUser`, `dismissed`,
  `postponed`. `ActionSteps` contains the text returned by the recommendation. The tab returns no rows
  without Entra ID P1/P2. `Status` cells render red for `active`, green when the value contains `completed`,
  gray for `dismissed`, yellow for `postponed`. `Priority` renders red/orange/yellow for
  `high`/`medium`/`low`.
- **Enterprise application inventory**: `Audience` renders orange when the value contains `Multiple` or `Personal`.
  `VerifiedPublisher` renders `Unverified` in yellow when empty.
- **Application credentials**: `ClientSecrets` renders orange when non-empty. `SecretExpiry` and `CertExpiry`
  contain the `endDateTime` values returned by Graph.
- **Delegated permission grants**: `ConsentType` renders red when the value is `AllPrincipals`. `Scopes`
  renders red when it contains `Directory.ReadWrite` or `full_access`, orange when it contains `Mail.` or
  `Files.ReadWrite`.
- **Microsoft Graph app permissions**: `AppRoleId` cells render with a label and color for the IDs in the
  table below; other IDs render unchanged.

`AppRoleId` label and color reference:

| App role ID | Microsoft Graph permission | Render |
| --- | --- | --- |
| `19dbc75e-c2e2-444c-a770-ec69d8559fc7` | Directory.ReadWrite.All | red |
| `9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8` | RoleManagement.ReadWrite.Directory | red |
| `1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9` | Application.ReadWrite.All | red |
| `06b708a9-e830-4db3-a914-8e69da51d44f` | AppRoleAssignment.ReadWrite.All | red |
| `e2a3a72e-5f79-4c64-b1b1-878b674786c9` | Mail.ReadWrite | orange |
| `75359482-378d-4052-8f01-80520e7db3cd` | Files.ReadWrite.All | orange |

The `ClientSP`, `ResourceSP`, `User`, and `AppSP` columns contain object-id GUIDs. To map a GUID to a name,
look it up in **Entra ID → Enterprise applications**.

## Step 5 — Software Vulnerabilities (Defender)

Set the **Subscriptions**, **Severity**, and **Vendor** filters, then select a tab.

| Tab | Content |
| --- | --- |
| **CVE Findings** | Each CVE finding with severity, CVSS, software, vendor, patchability, and resource. |
| **Vulnerable Software** | Software inventory aggregated by vendor/product with device counts. |
| **Affected Devices** | Devices with Critical/High counts and distinct CVE counts. |
| **End-of-Support Software** | Products reported as unsupported or approaching end of support. |

Data sources (Azure Resource Graph):

- `microsoft.security/assessments/subassessments` — CVE findings, filtered to
  `ServerVulnerabilityAssessment`, `ContainerRegistryVulnerability`, and `ContainerImageVulnerability`, and
  to vendors that do not contain `microsoft`.
- `microsoft.security/softwareinventories` — software inventory, including vendor, version, and
  end-of-support fields.

## Notes

- The Entra tabs use the workbook Microsoft Graph data source (`MsGraphEndpoint/1.0`, `GETARRAY`). `GETARRAY`
  follows `@odata.nextLink` and returns the merged `value` array, so JSONPath columns reference `$.field`
  directly.
- The Defender queries use `coalesce(...)` to read `cveId`/`cve`, `softwareName`/`packageName`, and
  `cvss30Score`/`cvssScore`/`cvss`, because these property names vary by plan.
- To include Microsoft products, remove the `!contains 'microsoft'` filters in the software queries.

## Alternative — Microsoft Graph via Postman

The `postman/` folder contains a collection and environment that call the same five Graph endpoints used by
the Entra ID tabs, so you can retrieve the data from a client instead of the workbook.

Setup:

1. Register an app in **Entra ID → App registrations**. Add a client secret. Add the Microsoft Graph
   **application** permissions `DirectoryRecommendations.Read.All`, `Application.Read.All`,
   `Directory.Read.All`, then grant admin consent.
2. In Postman, import both files from `postman/`.
3. Select the **Third-Party Vulnerabilities - Graph** environment and set `tenantId`, `clientId`, and
   `clientSecret`.
4. Send any request. The collection pre-request script requests an app-only token, caches it in
   `access_token`, and sends it as a bearer token.

Requests:

| Request | Endpoint |
| --- | --- |
| 1. Entra recommendations | `GET /beta/directory/recommendations` |
| 2. Service principals (app inventory) | `GET /v1.0/servicePrincipals` |
| 3. Applications (credentials) | `GET /v1.0/applications` |
| 4. OAuth2 permission grants (delegated consents) | `GET /v1.0/oauth2PermissionGrants` |
| 5. App role assignments to Microsoft Graph | `GET /v1.0/servicePrincipals(appId='00000003-…')/appRoleAssignedTo` |

Each response returns a `value` array. When more results exist, the response includes `@odata.nextLink`;
the request's test script stores it in the `nextLink` environment variable. Send the **Next page** request
to retrieve the following page, and repeat until `nextLink` is no longer set.

## Tests

The `tests/` folder contains Pester tests that validate the artifacts in this repository: JSON parses,
the workbook structure and content, Bicep compilation and settings, the Postman collection, and the
syntax of the embedded Postman JavaScript.

Prerequisites:

- PowerShell 7 or later.
- Pester 5 or later (`Install-Module Pester -Scope CurrentUser`).
- Node.js (used to syntax-check the Postman scripts).
- Azure CLI (used to compile the Bicep template).

Run from the repository root:

```powershell
Invoke-Pester -Path ./tests -Output Detailed
```

The run reports the number of tests passed and failed.
