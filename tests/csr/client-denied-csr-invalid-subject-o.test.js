const { createCSR, deleteCSR } = require('#helpers/csrHelpers.js')
const { waitForCSRStatus } = require('#helpers/waitForCSRApproval.js')
const { generateCSR } = require('#helpers/generateCSR.js')
const { clientCSR } = require('#helpers/csrTemplates.js')
const { csrTests } = require('#fixtures/testData.js')

const { nodeName } = csrTests.nodeData
const { clientCSRName } = csrTests

describe('CSR denied - invalid Subject Organization', () => {
  describe('when organization is system:master', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:master',
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

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(clientCSRName, 'Denied')
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(clientCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(clientCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when organization has a typo', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodez',
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

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(clientCSRName, 'Denied')
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(clientCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(clientCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when organization is empty', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: '',
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

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(clientCSRName, 'Denied')
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(clientCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(clientCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when organization is missing', () => {
    test('should create CSR', async () => {
      const csrData = {
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

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(clientCSRName, 'Denied')
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(clientCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(clientCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when organization contains random characters', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'qwerty123',
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

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(clientCSRName, 'Denied')
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
