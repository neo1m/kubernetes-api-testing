const { createCSR, deleteCSR, getCSRList } = require('#helpers/csrHelpers.js')
const { waitForCSRStatus } = require('#helpers/waitForCSRApproval.js')
const { generateCSR } = require('#helpers/generateCSR.js')
const { clientCSR } = require('#helpers/csrTemplates.js')
const { clientCSRName, nodeData } = require('#fixtures/testData.js')

const { nodeName } = nodeData
const WAIT_TIMEOUT = 60000

describe('CSR denied - invalid CertificateSigningRequest.spec.usages', () => {
  describe('when required spec usage "client auth" is missing', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: `system:node:${nodeName}`,
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.usages = [
        "digital signature",
      ]
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

  describe('when required spec usage "digital signature" is missing', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: `system:node:${nodeName}`,
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.usages = [
        "client auth",
      ]
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

  describe('when spec usages have extra values', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: `system:node:${nodeName}`,
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.usages = [
        "digital signature",
        "client auth",
        "server auth",
        "cert sign",
        "any",
      ]
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

  describe('when spec usages is empty', () => {
    test('should not create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: `system:node:${nodeName}`,
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.usages = []
      newCSR.spec.username = `system:bootstrap:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(422)
    })

    test('should not exist CSR', async () => {
      const { status, body } = await getCSRList()
      const csrNames = body.items.map(csr => csr.metadata.name)
      expect(status).toBe(200)
      expect(csrNames).not.toContain(clientCSRName)
    })
  })

  describe('when spec usages have typo in values', () => {
    test('should not create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: `system:node:${nodeName}`,
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.usages = [
        "digital signature",
        "client au",
      ]
      newCSR.spec.username = `system:bootstrap:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(422)
    })

    test('should not exist CSR', async () => {
      const { status, body } = await getCSRList()
      const csrNames = body.items.map(csr => csr.metadata.name)
      expect(status).toBe(200)
      expect(csrNames).not.toContain(clientCSRName)
    })
  })
})
