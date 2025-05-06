const { createCSR, deleteCSR } = require('#helpers/csrHelpers.js')
const { waitForCSRStatus } = require('#helpers/waitForCSRApproval.js')
const { generateCSR } = require('#helpers/generateCSR.js')
const { serverCSR } = require('#helpers/csrTemplates.js')
const { csrTests } = require('#fixtures/testData.js')

const { nodeName, externalIP, internalIP } = csrTests.nodeData
const { serverCSRName } = csrTests
const WAIT_TIMEOUT = 60000

describe('CSR denied: invalid subject Organization', () => {
  describe('when organization is system:master', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:master',
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

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(serverCSRName, 'Denied', WAIT_TIMEOUT)
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(serverCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(serverCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when organization has a typo', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes1',
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

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(serverCSRName, 'Denied', WAIT_TIMEOUT)
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(serverCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(serverCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when organization is empty', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: '',
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

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(serverCSRName, 'Denied', WAIT_TIMEOUT)
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(serverCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(serverCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when organization is missing', () => {
    test('should create CSR', async () => {
      const csrData = {
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

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(serverCSRName, 'Denied', WAIT_TIMEOUT)
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(serverCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(serverCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when organization contains random characters', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'qwerty123',
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

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(serverCSRName, 'Denied', WAIT_TIMEOUT)
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(serverCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(serverCSRName)
      expect(status).toBe(200)
    })
  })
})
