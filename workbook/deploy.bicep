@description('Display name shown in the Azure Monitor Workbooks gallery.')
param workbookDisplayName string = 'Third-Party Application Vulnerabilities (Entra ID + Defender)'

@description('Azure region for the workbook resource.')
param location string = resourceGroup().location

@description('Stable GUID for the workbook. Keep it constant to update the same workbook on redeploy.')
param workbookId string = guid(resourceGroup().id, workbookDisplayName)

// Workbook gallery category. 'workbook' = the generic Azure Monitor gallery.
var workbookSourceId = 'azure monitor'

resource workbook 'Microsoft.Insights/workbooks@2023-06-01' = {
  name: workbookId
  location: location
  kind: 'shared'
  properties: {
    displayName: workbookDisplayName
    category: 'sentinel'
    sourceId: workbookSourceId
    version: '1.0'
    serializedData: loadTextContent('third-party-vulnerabilities.workbook.json')
  }
}

output workbookResourceId string = workbook.id
output workbookName string = workbook.name
