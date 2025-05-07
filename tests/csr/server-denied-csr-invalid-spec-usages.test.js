const { createCSR, deleteCSR, getCSRList } = require('#helpers/csrHelpers.js')
const { waitForCSRStatus } = require('#helpers/waitForCSRApproval.js')
const { generateCSR } = require('#helpers/generateCSR.js')
const { serverCSR } = require('#helpers/csrTemplates.js')
const { csrTests } = require('#fixtures/testData.js')

const { nodeName, externalIP, internalIP } = csrTests.nodeData
const { serverCSRName } = csrTests

describe('[CSR denied]', () => {
  describe('[when required spec.usages "server auth" is missing]', () => {
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
      newCSR.spec.usages = [
        "digital signature",
      ]
      newCSR.spec.username = `system:node:${nodeName}`
  
      const { status } = await createCSR(newCSR)
      expect(status).toBe(201)
    })

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(serverCSRName, 'Denied')
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(serverCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(serverCSRName)
      expect(status).toBe(200)
    })
  })

  describe('[when required spec.usages "digital signature" is missing]', () => {
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
      newCSR.spec.usages = [
        "server auth",
      ]
      newCSR.spec.username = `system:node:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(201)
    })

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(serverCSRName, 'Denied')
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(serverCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })
  
    test('should delete CSR', async () => {
      const { status } = await deleteCSR(serverCSRName)
      expect(status).toBe(200)
    })
  })

  describe('[when spec.usages have extra values]', () => {
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
      newCSR.spec.usages = [
        "digital signature",
        "client auth",
        "server auth",
        "cert sign",
        "any",
      ]
      newCSR.spec.username = `system:node:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(201)
    })

    test('should deny CSR', async () => {
      const { status, body } = await waitForCSRStatus(serverCSRName, 'Denied')
      expect(status).toBe(200)
      expect(body.metadata.name).toBe(serverCSRName)
      expect(body.status.conditions[0].type).toBe('Denied')
    })

    test('should delete CSR', async () => {
      const { status } = await deleteCSR(serverCSRName)
      expect(status).toBe(200)
    })
  })

  describe('[when spec.usages is empty]', () => {
    test('should not create CSR', async () => {
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
      newCSR.spec.usages = []
      newCSR.spec.username = `system:node:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(422)
    })

    test('should not exist CSR', async () => {
      const { status, body } = await getCSRList()
      const csrNames = body.items.map(csr => csr.metadata.name)
      expect(status).toBe(200)
      expect(csrNames).not.toContain(serverCSRName)
    })
  })

  describe('[when spec.usages have typo in values]', () => {
    test('should not create CSR', async () => {
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
      newCSR.spec.usages = [
        "digital signa",
        "server auth",
      ]
      newCSR.spec.username = `system:node:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(422)
    })

    test('should not exist CSR', async () => {
      const { status, body } = await getCSRList()
      const csrNames = body.items.map(csr => csr.metadata.name)
      expect(status).toBe(200)
      expect(csrNames).not.toContain(serverCSRName)
    })
  })
})
