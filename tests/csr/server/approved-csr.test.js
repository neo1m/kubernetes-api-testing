const { createCSR, deleteCSR } = require('#helpers/csrHelpers.js')
const { waitForCSRStatus } = require('#helpers/waitForCSRApproval.js')
const { generateCSR } = require('#helpers/generateCSR.js')
const { serverCSR } = require('#helpers/csrTemplates.js')
const { serverCSRName, nodeData } = require('#fixtures/testData.js')

const { nodeName, externalIP, internalIP } = nodeData

describe('CSR approved - all data is valid', () => {
  test('should create CSR', async () => {
    const csrData = {
      organizationName: 'system:nodes',
      commonName: `system:node:${nodeName}`,
      altNames: [
        { type: 'ip', value: internalIP },
        { type: 'ip', value: externalIP },
      ]
    }

    const { csrBase64 } = generateCSR(csrData)

    const newCSR = JSON.parse(JSON.stringify(serverCSR))
    newCSR.metadata.name = serverCSRName
    newCSR.spec.request = csrBase64
    newCSR.spec.username = `system:node:${nodeName}`

    const { status } = await createCSR(newCSR)
    expect(status).toBe(201)
  })

  test('should approve CSR', async () => {
    const { status, body } = await waitForCSRStatus(serverCSRName, 'Approved', 60000)
    expect(status).toBe(200)
    expect(body.metadata.name).toBe(serverCSRName)
    expect(body.status.conditions[0].type).toBe('Approved')
  })

  test('should delete CSR', async () => {
    const { status } = await deleteCSR(serverCSRName)
    expect(status).toBe(200)
  })
})
