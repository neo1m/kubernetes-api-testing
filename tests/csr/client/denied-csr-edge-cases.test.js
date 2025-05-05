const { createCSR, getCSRList } = require('#helpers/csrHelpers.js')
const { generateCSR } = require('#helpers/generateCSR.js')
const { clientCSR } = require('#helpers/csrTemplates.js')
const { clientCSRName, nodeData } = require('#fixtures/testData.js')

const { nodeName } = nodeData

describe('CSR denied - edge cases with invalid structure or malformed requests', () => {
  describe('when CSR base64 structure is empty', () => {
    test('should not create CSR', async () => {
      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = ''
      newCSR.spec.username = `system:node:${nodeName}`

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

  describe('when CSR base64 structure is incorrect', () => {
    test('should not create CSR', async () => {
      const csrData = {
        organizationName: 'system:nodes',
        commonName: `system:node:${nodeName}`,
      }

      const { csrBase64 } = generateCSR(csrData)

      const newCSR = JSON.parse(JSON.stringify(clientCSR))
      newCSR.metadata.name = clientCSRName
      newCSR.spec.request = 'qwerty123' + csrBase64
      newCSR.spec.username = `system:node:${nodeName}`

      const { status } = await createCSR(newCSR)
      expect(status).toBe(400)
    })

    test('should not exist CSR', async () => {
      const { status, body } = await getCSRList()
      const csrNames = body.items.map(csr => csr.metadata.name)
      expect(status).toBe(200)
      expect(csrNames).not.toContain(clientCSRName)
    })
  })
})
