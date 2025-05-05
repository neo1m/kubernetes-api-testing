const { createCSR, deleteCSR } = require('#helpers/csrHelpers.js')
const { waitForCSRStatus } = require('#helpers/waitForCSRApproval.js')
const { generateCSR } = require('#helpers/generateCSR.js')
const { clientCSR } = require('#helpers/csrTemplates.js')
const { clientCSRName, nodeData } = require('#fixtures/testData.js')

const { nodeName } = nodeData
const WAIT_TIMEOUT = 60000

describe('CSR denied - invalid Subject Common Name', () => {
  describe('when common name in CSR is empty', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: '',
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.username = `system:bootstrap:${nodeName}`

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

  describe('when common name in CSR is missing', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.username = `system:bootstrap:${nodeName}`
  
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

  describe('when common name in CSR contains random characters', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: 'qwerty123',
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.username = `system:bootstrap:${nodeName}`

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

  describe('when common name in API request is empty', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: `system:node:${nodeName}`,
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.username = ''

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

  describe('when common name in API request is missing', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: `system:node:${nodeName}`,
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64

      delete newCSR.spec.username
  
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

  describe('when common name in API request contains random characters', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: `system:node:${nodeName}`,
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.username = 'qwerty123'

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
