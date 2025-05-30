const fs = require('fs')
const path = require('path')
const fetch = require('node-fetch')

// Базовый конфиг
const { outputDir, kubeAuthFiles, kube } = require('#root/config.js')

// Тестовые данные
const { csrTests } = require('#fixtures/testData.js')

// Вспомогательные методы
const {
  createDirectoryIfNotExists,
  removeDirectory,
  createHttpsAgent,
} = require('#helpers/common.js')

// Методы для работы с openssl
const {
  generateKeys,
  generateCSR,
  signCertificate,
} = require('#helpers/openssl.js')

// Адрес API
const baseURL = `https://${kube.host}:${kube.port}`
const csrPath = '/apis/certificates.k8s.io/v1/certificatesigningrequests'

// Тестовые данные
const csrName = csrTests.clientCSRName
const nodeData = csrTests.nodeData

// Для данных spec.usages запрещено создание CSR
const csrCreationForbiddenRequest = [
  {
    name: 'empty string as request',
    request: ''
  },
  {
    name: 'whitespace only request',
    request: '   '
  },
  {
    name: 'random non-base64 string',
    request: 'not-base64-data!'
  },
  {
    name: 'valid base64, but not a CSR',
    request: Buffer.from('this is not a CSR').toString('base64')
  },
  {
    name: 'corrupted base64 with invalid characters',
    request: '!!!@@@###'
  },
  {
    name: 'valid base64 but incomplete PEM block',
    request: Buffer.from('-----BEGIN CERTIFICATE REQUEST-----\nMIIC...').toString('base64')
  },
  {
    name: 'double encoded base64 string',
    request: Buffer.from(Buffer.from('this is not a CSR').toString('base64')).toString('base64')
  },
]

beforeAll(() => {
  createDirectoryIfNotExists(outputDir)
})

describe('[CSR denied]', () => {
  describe.each([
    ...csrCreationForbiddenRequest,
  ])
    ('[when spec.request in CSR equal "$name"]', ({ name, request }) => {
      // Директория и файлы для каждого тестового набора данных
      const fileName = path.basename(__filename, path.extname(__filename))
      const testCaseName = name.replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_+|_+$/g, '')
      const testCaseDir = path.join(outputDir, fileName, testCaseName)
      const testFiles = {
        privateKey: path.join(testCaseDir, 'client.key'),
        publicKey: path.join(testCaseDir, 'client.pub'),
        csr: path.join(testCaseDir, 'client.csr'),
        ext: path.join(testCaseDir, 'v3.ext'),
        crt: path.join(testCaseDir, 'client.crt'),
      }

      beforeAll(() => {
        // Создаем отдельную директорию для каждого тестового набора данных
        createDirectoryIfNotExists(testCaseDir)
      })

      test('should prepare openssl files', async () => {
        // Subject
        const subjectList = [
          `CN=system:bootstrap:${nodeData.nodeName}`,
          `O=system:bootstrappers`,
          `O=system:bootstrappers:kubeadm:default-node-token`,
        ]

        // Генерируем ключи, конфиги, CSR и сертификат для клиента
        generateKeys(testFiles.privateKey, testFiles.publicKey)
        generateCSR(testFiles.privateKey, testFiles.csr, subjectList)
        signCertificate(testFiles.csr, testFiles.crt, kubeAuthFiles.caCrt, kubeAuthFiles.caKey)

        // Проверки
        expect(fs.existsSync(testFiles.privateKey)).toBe(true)
        expect(fs.existsSync(testFiles.publicKey)).toBe(true)
        expect(fs.existsSync(testFiles.csr)).toBe(true)
        expect(fs.existsSync(testFiles.crt)).toBe(true)
      })

      test('should not create CSR', async () => {
        // Настройка HTTPS агента с mTLS
        const httpsAgent = createHttpsAgent(testFiles.crt, testFiles.privateKey, kubeAuthFiles.caCrt)

        // API тело запроса
        const certificateSigningRequest = {
          apiVersion: "certificates.k8s.io/v1",
          kind: "CertificateSigningRequest",
          metadata: {
            name: csrName
          },
          spec: {
            request: request,
            signerName: "kubernetes.io/kube-apiserver-client-kubelet",
            usages: [
              "digital signature",
              "client auth"
            ],
          }
        }

        // Запрос на создание CSR
        const res = await fetch(`${baseURL}${csrPath}`, {
          method: 'POST',
          body: JSON.stringify(certificateSigningRequest),
          headers: { 'Content-Type': 'application/json' },
          agent: httpsAgent,
        })

        // Возможные статусы ответа
        const expectedStatus = [
          400, // CSR не создан (Bad Request)
          401, // CSR не создан (Unauthorized)
          403, // CSR не создан (Forbidden)
          422, // CSR не создан (Unprocessable Entity)
        ]
        console.log(`[CSR CREATE] Received status "${res.status}"`)

        // Проверки
        expect(expectedStatus).toContain(res.status)
      })
    })
})
