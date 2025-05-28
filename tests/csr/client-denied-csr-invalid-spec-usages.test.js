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
  encodeCSRToBase64,
  signCertificate,
} = require('#helpers/openssl.js')

// Адрес API
const baseURL = `https://${kube.host}:${kube.port}`
const csrPath = '/apis/certificates.k8s.io/v1/certificatesigningrequests'

// Тестовые данные
const csrName = csrTests.clientCSRName
const nodeData = csrTests.nodeData

// Для данных spec.groups запрос на создание CSR отклоняется
const csrCreationForbiddenUsages = [
  {
    name: 'valid usages as one string',
    usages: ['digital signature client auth'],
  },
  {
    name: 'case mismatch in usages',
    usages: ['Digital Signature', 'Client Auth'],
  },
  {
    name: 'typo in digital signature',
    usages: ['digitaal signature', 'client auth'],
  },
  {
    name: 'typo in client auth',
    usages: ['digital signature', 'client authentication'],
  },
  {
    name: 'duplicates only one valid usage',
    usages: ['client auth', 'client auth'],
  },
  {
    name: 'empty usages list',
    usages: [],
  },
  {
    name: 'one valid and one misspelled usage',
    usages: ['digital signature', 'clint auth'],
  },
  {
    name: 'both usages misspelled',
    usages: ['digitl signatur', 'clint aut'],
  },
]

// Для данных spec.usages отклоняется созданный CSR
const csrDeniedUsages = [
  {
    name: 'valid usages plus one extra server auth',
    usages: ['digital signature', 'client auth', 'server auth'],
  },
  {
    name: 'valid usages plus one extra client auth',
    usages: ['digital signature', 'client auth', 'client auth'],
  },
  {
    name: 'valid usages plus one extra digital signature',
    usages: ['digital signature', 'client auth', 'digital signature'],
  },
  {
    name: 'valid usages plus two extras',
    usages: ['digital signature', 'client auth', 'server auth', 'key encipherment'],
  },
  {
    name: 'only one unrelated usage',
    usages: ['code signing'],
  },
  {
    name: 'unrelated usages only',
    usages: ['key agreement', 'email protection'],
  },
  {
    name: 'all known usages except valid ones',
    usages: [
      'signing',
      'content commitment',
      'key encipherment',
      'key agreement',
      'data encipherment',
      'cert sign',
      'crl sign',
      'encipher only',
      'decipher only',
      'any',
      'server auth',
      'code signing',
      'email protection',
      's/mime',
      'ipsec end system',
      'ipsec tunnel',
      'ipsec user',
      'timestamping',
      'ocsp signing',
      'microsoft sgc',
      'netscape sgc'
    ],
  },
  {
    name: 'unrelated usages and one valid',
    usages: ['client auth', 'server auth'],
  },
  {
    name: 'valid usages mixed with multiple extras',
    usages: ['digital signature', 'client auth', 'any', 'server auth', 'timestamping'],
  },
  {
    name: 'only extras from microsoft and netscape',
    usages: ['microsoft sgc', 'netscape sgc'],
  },
  {
    name: 'ipsec usages only',
    usages: ['ipsec end system', 'ipsec tunnel', 'ipsec user'],
  },
  {
    name: 'timestamping only',
    usages: ['timestamping'],
  },
  {
    name: 'ocsp signing only',
    usages: ['ocsp signing'],
  },
]

beforeAll(() => {
  createDirectoryIfNotExists(outputDir)
})

describe('[CSR denied]', () => {
  describe.each([
    ...csrCreationForbiddenUsages,
    ...csrDeniedUsages,
  ])
    ('[when spec.usages equal "$name"]', ({ name, usages }) => {
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
        const subject = [
          `CN=system:bootstrap:${nodeData.nodeName}`,
          `O=system:bootstrappers`,
          `O=system:bootstrappers:kubeadm:default-node-token`,
        ]

        // Генерируем ключи, конфиги, CSR и сертификат для клиента
        generateKeys(testFiles.privateKey, testFiles.publicKey)
        generateCSR(testFiles.privateKey, testFiles.csr, subject)
        signCertificate(testFiles.csr, testFiles.crt, kubeAuthFiles.caCrt, kubeAuthFiles.caKey)

        // Проверки
        expect(fs.existsSync(testFiles.privateKey)).toBe(true)
        expect(fs.existsSync(testFiles.publicKey)).toBe(true)
        expect(fs.existsSync(testFiles.csr)).toBe(true)
        expect(fs.existsSync(testFiles.crt)).toBe(true)
      })

      test('should create CSR', async () => {
        // Настройка HTTPS агента с mTLS
        const httpsAgent = createHttpsAgent(testFiles.crt, testFiles.privateKey, kubeAuthFiles.caCrt)

        // CSR в формате base64
        const base64CSR = encodeCSRToBase64(testFiles.csr)

        // API тело запроса
        const certificateSigningRequest = {
          apiVersion: "certificates.k8s.io/v1",
          kind: "CertificateSigningRequest",
          metadata: {
            name: csrName
          },
          spec: {
            request: base64CSR,
            signerName: "kubernetes.io/kube-apiserver-client-kubelet",
            usages: usages,
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
          201, // CSR успешно создан (Created)
          401, // CSR не создан (Unauthorized)
          403, // CSR не создан (Forbidden)
          422, // CSR не создан (Unprocessable Entity)
        ]
        console.log(`[CSR CREATE] Received status "${res.status}"`)

        // Проверки
        expect(expectedStatus).toContain(res.status)
      })

      test('should deny CSR', async () => {
        // Настройка HTTPS агента с mTLS
        const httpsAgent = createHttpsAgent(testFiles.crt, testFiles.privateKey, kubeAuthFiles.caCrt)

        // Максимальное время ожидания
        const maxRetryTime = 60000
        const retryInterval = 5000
        const expectedStatus = 'Denied'
        const startTime = Date.now()

        // Цикл запросов
        while (Date.now() - startTime < maxRetryTime) {
          const res = await fetch(`${baseURL}${csrPath}/${csrName}`, {
            method: 'GET',
            agent: httpsAgent,
          })

          const body = await res.json()
          const lastStatus = body.status?.conditions?.[0]?.type || ''

          // CSR отсутствует или нет доступа (не удалось создать ранее)
          if (res.status !== 200) {
            console.log(`[CSR CHECK] Non-200 status "${res.status}" - stopping watch`)
            return
          }

          // CSR существует, статус соответствует искомому
          if (lastStatus === expectedStatus) {
            console.log(`[CSR CHECK] Resource has expected status "${expectedStatus}" - stopping watch`)
            expect(res.status).toBe(200)
            expect(body.metadata.name).toBe(csrName)
            expect(lastStatus).toBe(expectedStatus)
            return
          }

          // CSR существует, но статус не соответствует искомому
          if (lastStatus && lastStatus !== expectedStatus) {
            console.log(`[CSR CHECK] Unexpected CSR status "${lastStatus}" - throwing error`)
            throw new Error(`Unexpected CSR status "${lastStatus}"`)
          }

          // CSR существует, но статус ещё не определён — продолжаем ждать
          console.log(`[CSR CHECK] Status not yet set - continuing to wait`)
          await new Promise(resolve => setTimeout(resolve, retryInterval))
        }

        // Если дошли сюда - значит искомый статус CSR не получен за отведённое время
        throw new Error(`Timeout waiting for CSR "${csrName}" to have status "${expectedStatus}" within ${maxRetryTime / 1000} seconds`)
      })

      test('should delete CSR', async () => {
        // Настройка HTTPS агента с mTLS (для удаления CSR после тестов используем доступы от основного клиента)
        const httpsAgent = createHttpsAgent(kubeAuthFiles.clientCert, kubeAuthFiles.clientKey, kubeAuthFiles.caCrt)

        // Запрос на удаление CSR
        const res = await fetch(`${baseURL}${csrPath}/${csrName}`, {
          method: 'DELETE',
          agent: httpsAgent,
        })

        // Возможные статусы ответа
        const expectedStatus = [
          200, // CSR успешно удален
          403, // CSR не найден (нет доступа)
          404, // CSR не найден (не удалось создать ранее)
        ]
        console.log(`[CSR DELETE] Received status "${res.status}"`)

        // Проверки
        expect(expectedStatus).toContain(res.status)
      })
    })
})
