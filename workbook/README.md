# Third-Party Application Vulnerabilities Workbook

An Azure Monitor workbook for **DevSecOps remediation planning** across two domains, selectable from a
top-level **domain selector**:

1. **🔐 Entra ID Applications** — third-party & in-house **app registrations / enterprise applications**,
   assessed for risky permissions, credential hygiene, risky OAuth consents and **Microsoft Entra
   recommendations** (with *addressed / not-addressed* status and remediation guidance). Powered by
   **Microsoft Graph**.
2. **💿 Software Vulnerabilities (Defender)** — non-Microsoft **software CVEs** discovered by **Microsoft
   Defender Vulnerability Management (MDVM)** via Azure Resource Graph.

---

## 🔐 Entra ID Applications

Answers: *which registered third-party apps have known weaknesses, what are they, have they been addressed,
and how do I remediate the rest?*

| Tab | Content | Graph endpoint |
| --- | --- | --- |
| **Remediation (Entra Recommendations)** | Microsoft Entra recommendations with **Status** (active vs. completed/dismissed = *addressed*), **Priority**, and **Action Steps** (native remediation guidance). | `GET /beta/directory/recommendations` |
| **Third-Party App Inventory** | Enterprise applications (service principals) — publisher, **verified publisher**, owner tenant, sign-in audience, enabled state. Unverified / external-tenant apps are your third-party attack surface. | `GET /v1.0/servicePrincipals` |
| **Credential Hygiene** | App registrations using **client secrets** vs. **certificates**, with expiry dates and creation date. Secrets are highlighted (prefer certificates / managed identity). | `GET /v1.0/applications` |
| **Risky Delegated Consents** | OAuth2 permission grants — **tenant-wide admin consent** (`AllPrincipals`) and sensitive scopes (Mail, Files, Directory.ReadWrite) are highlighted. | `GET /v1.0/oauth2PermissionGrants` |
| **High-Privilege App Permissions** | **Application (app-only)** Microsoft Graph permissions granted to apps. The most dangerous role IDs are color-coded and labelled. | `GET /v1.0/servicePrincipals(appId='00000003-…')/appRoleAssignedTo` |

### "Have they been addressed?" + guidance
The **Remediation** tab is the planning hub: Microsoft Entra recommendations carry a `status`
(`active` = open, `completedBySystem`/`completedByUser` = addressed, `dismissed`/`postponed`) **plus**
`actionSteps` containing the official remediation guidance. The other tabs surface the raw signals
(credentials, consents, permissions) so you can prioritise apps the recommendations don't yet cover.

### Dangerous app-role (app-only) reference

| App role ID | Microsoft Graph permission |
| --- | --- |
| `19dbc75e-c2e2-444c-a770-ec69d8559fc7` | Directory.ReadWrite.All |
| `9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8` | RoleManagement.ReadWrite.Directory |
| `1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9` | Application.ReadWrite.All |
| `06b708a9-e830-4db3-a914-8e69da51d44f` | AppRoleAssignment.ReadWrite.All |
| `e2a3a72e-5f79-4c64-b1b1-878b674786c9` | Mail.ReadWrite |
| `75359482-378d-4052-8f01-80520e7db3cd` | Files.ReadWrite.All |

> Delegated/app principal IDs in the consents and permissions tabs are **object-id GUIDs** — workbooks
> can't join them to friendly names. Use the *Application* column (where present) or look up the GUID in
> **Entra ID → Enterprise applications**.

### Least-privilege access (Microsoft Graph, delegated)

The signed-in user runs the Graph queries with **delegated** permissions. Grant the **smallest** role that
covers all five tabs:

- **Recommended role:** **Global Reader** *(read-only, covers apps, service principals, OAuth grants and
  recommendations)*. **Security Reader** also works for most tabs.
- **Granular scopes** (if consenting app permissions explicitly):
  `DirectoryRecommendations.Read.All`, `Application.Read.All`, `Directory.Read.All`,
  `DelegatedPermissionGrant.Read.All`.
- The **Remediation** tab additionally requires **Microsoft Entra ID P1/P2** licensing (recommendations API).

---

## 💿 Software Vulnerabilities (Defender)

| Tab | Content |
| --- | --- |
| **CVE Findings** | Every third-party CVE finding with severity, CVSS, affected software, vendor, patchability and resource. |
| **Vulnerable Software** | Third-party software inventory aggregated by vendor/product with device counts. |
| **Affected Devices** | Devices ranked by Critical/High counts and total distinct CVEs. |
| **End-of-Support Software** | Unsupported / soon-to-be-EOS third-party products. |

Filters: **Subscriptions**, **Severity**, **Vendor**.

### Data sources (Azure Resource Graph)

- `microsoft.security/assessments/subassessments` — Defender vulnerability findings (CVEs). Filtered to
  `ServerVulnerabilityAssessment`, `ContainerRegistryVulnerability`, `ContainerImageVulnerability` and to
  vendors that do **not** contain "microsoft".
- `microsoft.security/softwareinventories` — Defender software inventory (vendor, version, end-of-support).

### Prerequisites

- **Microsoft Defender for Servers Plan 2** or **Defender Vulnerability Management** enabled on the resources.
- **Reader** role on the selected subscriptions.

---

## Deploy

Workbook authoring/saving needs **Monitoring Contributor** or **Workbook Contributor** on the target
resource group, in addition to the data-read roles above.

### Option A — Import in the portal
1. Azure Portal → **Monitor** → **Workbooks** → **+ New** → **Advanced Editor** (`</>`).
2. Paste the contents of [`third-party-vulnerabilities.workbook.json`](./third-party-vulnerabilities.workbook.json).
3. **Apply** → **Done Editing** → **Save**.

### Option B — Bicep (repeatable)
```powershell
az group create --name rg-security-workbooks --location westeurope

az deployment group create `
  --resource-group rg-security-workbooks `
  --template-file deploy.bicep
```

## Notes
- The Entra tabs use the workbook **Microsoft Graph** data source (`MsGraphEndpoint/1.0`, `GETARRAY`), which
  auto-pages `@odata.nextLink` and returns the merged `value` array, so JSONPath columns reference `$.field`
  directly.
- Defender MDVM property names can vary by plan; queries use `coalesce(...)` to tolerate
  `cveId`/`cve`, `softwareName`/`packageName`, and `cvss30Score`/`cvssScore`/`cvss`.
- To include Microsoft products too, remove the `!contains 'microsoft'` filters in the software queries.
