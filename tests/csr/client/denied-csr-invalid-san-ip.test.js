const { createCSR, deleteCSR } = require('#helpers/csrHelpers.js')
const { waitForCSRStatus } = require('#helpers/waitForCSRApproval.js')
const { generateCSR } = require('#helpers/generateCSR.js')
const { clientCSR } = require('#helpers/csrTemplates.js')
const { csrTests } = require('#fixtures/testData.js')

const { nodeName, externalIP, internalIP } = csrTests.nodeData
const { clientCSRName } = csrTests
const WAIT_TIMEOUT = 60000

describe('CSR denied - Subject Alternative Names should not exist for client node', () => {
  describe('when SAN consists of ip values', () => {
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

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.username = `system:node:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(201)
    })

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(clientCSRName, 'Denied', WAIT_TIMEOUT)
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(clientCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(clientCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when SAN consists of dns values', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: `system:node:${nodeName}`,
        altNames: [
          { type: 'dns', value: nodeName },
        ]
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.username = `system:node:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(201)
    })

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(clientCSRName, 'Denied', WAIT_TIMEOUT)
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(clientCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(clientCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when SAN consists of ip and dns values', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: `system:node:${nodeName}`,
        altNames: [
          { type: 'ip', value: internalIP },
          { type: 'ip', value: externalIP },
          { type: 'dns', value: nodeName },
        ]
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.username = `system:node:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(201)
    })

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(clientCSRName, 'Denied', WAIT_TIMEOUT)
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(clientCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(clientCSRName)
      expect(status).toBe(200)
    })
  })
})
