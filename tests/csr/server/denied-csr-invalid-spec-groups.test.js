const { createCSR, deleteCSR } = require('#helpers/csrHelpers.js')
const { waitForCSRStatus } = require('#helpers/waitForCSRApproval.js')
const { generateCSR } = require('#helpers/generateCSR.js')
const { serverCSR } = require('#helpers/csrTemplates.js')
const { serverCSRName, nodeData } = require('#fixtures/testData.js')

const { nodeName, externalIP, internalIP } = nodeData

describe('CSR denied - invalid CertificateSigningRequest.spec.groups', () => {
  describe('when required spec group "system:authenticated" is missing', () => {
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
      newCSR.spec.groups = [
        "system:nodes",
      ]
      newCSR.spec.username = `system:node:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(201)
    })

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(serverCSRName, 'Denied', 60000)
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(serverCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(serverCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when required spec group "system:nodes" is missing', () => {
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
      newCSR.spec.groups = [
        "system:authenticated",
      ]
      newCSR.spec.username = `system:node:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(201)
    })

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(serverCSRName, 'Denied', 60000)
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(serverCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(serverCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when required spec groups is empty', () => {
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
      newCSR.spec.groups = []
      newCSR.spec.username = `system:node:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(201)
    })

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(serverCSRName, 'Denied', 60000)
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(serverCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(serverCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when required spec groups have typo in values', () => {
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
      newCSR.spec.groups = [
        "system:nodez",
        "system:authenticated",
      ]
      newCSR.spec.username = `system:node:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(201)
    })

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(serverCSRName, 'Denied', 60000)
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(serverCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(serverCSRName)
      expect(status).toBe(200)
    })
  })

  describe('when required spec groups have extra values', () => {
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
      newCSR.spec.groups = [
        "system:nodes",
        "system:authenticated",
        "system:bootstrappers",
        "system:bootstrappers:kubeadm:default-node-token",
        "system:serviceaccounts",
      ]
      newCSR.spec.username = `system:node:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(201)
    })

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(serverCSRName, 'Denied', 60000)
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
