const { createCSR, deleteCSR } = require('#helpers/csrHelpers.js')
const { waitForCSRStatus } = require('#helpers/waitForCSRApproval.js')
const { generateCSR } = require('#helpers/generateCSR.js')
const { clientCSR } = require('#helpers/csrTemplates.js')
const { csrTests } = require('#fixtures/testData.js')

const { nodeName } = csrTests.nodeData
const { clientCSRName } = csrTests

describe('[CSR approved]', () => {
  describe('[when CSR data and API request are valid]', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: `system:node:${nodeName}`,
      }
  
      const { csrBase64 } = generateCSR(csrData)
  
      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.username = `system:bootstrap:${nodeName}`
  
      const { status } = await createCSR(newCSR)
      expect(status).toBe(201)
    })
  
    test('should approve CSR', async () => {
      const { status, body } = await waitForCSRStatus(clientCSRName, 'Approved')
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(clientCSRName)
      expect(body.status.conditions[0].type).toBe('Approved')
    })
  
    test('should delete CSR', async () => {
      const { status } = await deleteCSR(clientCSRName)
      expect(status).toBe(200)
    })
  })
})
