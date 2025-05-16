const { createCSR, deleteCSR } = require('#helpers/csrHelpers.js')
const { waitForCSRStatus } = require('#helpers/waitForCSRApproval.js')
const { generateCSR } = require('#helpers/generateCSR.js')
const { serverCSR } = require('#helpers/csrTemplates.js')
const { csrTests } = require('#fixtures/common-test-data.js')

const { nodeName, externalIP, internalIP } = csrTests.nodeData
const { serverCSRName } = csrTests

describe('[CSR denied]', () => {
  describe('[when Subject Common Name in CSR is empty]', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: '',
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

  describe('[when Subject Common Name in CSR is missing]', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
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

  describe('[when Subject Common Name in CSR contains random characters]', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: 'qwerty123',
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

  describe('[when spec.username in API request is empty]', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: '',
        altNames: [
          { type: 'ip', value: internalIP },
          { type: 'ip', value: externalIP },
        ]
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(serverCSR))
      newCSR.metadata.name = serverCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.username = ''

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

  describe('[when spec.username in API request is missing]', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        altNames: [
          { type: 'ip', value: internalIP },
          { type: 'ip', value: externalIP },
        ]
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(serverCSR))
      newCSR.metadata.name = serverCSRName
      newCSR.spec.request = csrBase64

      delete newCSR.spec.username

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

  describe('[when spec.username in API request contains random characters]', () => {
    test('should create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: 'qwerty123',
        altNames: [
          { type: 'ip', value: internalIP },
          { type: 'ip', value: externalIP },
        ]
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(serverCSR))
      newCSR.metadata.name = serverCSRName
      newCSR.spec.request = csrBase64
      newCSR.spec.username = 'qwerty123'

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
})
