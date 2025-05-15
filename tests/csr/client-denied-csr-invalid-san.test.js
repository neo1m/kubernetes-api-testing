const fs = require('fs')
const path = require('path')
const https = require('https')
const fetch = require('node-fetch')

// Базовый конфиг
const { outputDir, kubeAuthFiles, kube } = require('#root/config.js')

// Тестовые данные
const { csrTests } = require('#fixtures/testData.js')

// Вспомогательные методы
const { createDirectoryIfNotExists, removeDirectory } = require('#helpers/common.js')

// Методы для работы с openssl
const {
  generateKeys,
  generateCSR,
  createExtFile,
  encodeCSRToBase64,
  signCertificate,
} = require('#helpers/openssl.js')

// Пути к временным файлам
const testFiles = {
  privateKey: path.join(outputDir, 'client.key'),
  publicKey: path.join(outputDir, 'client.pub'),
  csr: path.join(outputDir, 'client.csr'),
  ext: path.join(outputDir, 'v3.ext'),
  crt: path.join(outputDir, 'client.crt')
}

// Адрес API
const baseURL = `https://${kube.host}:${kube.port}`
const csrPath = '/apis/certificates.k8s.io/v1/certificatesigningrequests'

// Тестовые данные
const csrName = csrTests.clientCSRName
const nodeData = csrTests.nodeData

// При наличии любого SAN отклоняется CSR
const sanList = [
  {
    name: 'san with external ip',
    san: [`IP:${nodeData.externalIP}`],
  },
  {
    name: 'san with internal ip',
    san: [`IP:${nodeData.internalIP}`],
  },
  {
    name: 'san with dns name',
    san: [`DNS:${nodeData.nodeName}`],
  },
  {
    name: 'san with external and internal ip',
    san: [`IP:${nodeData.externalIP}`, `IP:${nodeData.internalIP}`],
  },
  {
    name: 'san with ip and dns name',
    san: [`IP:${nodeData.internalIP}`, `DNS:${nodeData.nodeName}`],
  },
  {
    name: 'san with full combo of ip and dns',
    san: [`IP:${nodeData.externalIP}`, `IP:${nodeData.internalIP}`, `DNS:${nodeData.nodeName}`],
  },
  {
    name: 'san with duplicate entries',
    san: [`DNS:${nodeData.nodeName}`, `DNS:${nodeData.nodeName}`],
  },
  {
    name: 'san with duplicate external ip entries',
    san: [`DNS:${nodeData.externalIP}`, `DNS:${nodeData.externalIP}`],
  },
  {
    name: 'san with duplicate internal ip entries',
    san: [`DNS:${nodeData.internalIP}`, `DNS:${nodeData.internalIP}`],
  },
  {
    name: 'san with localhost ip',
    san: ['IP:127.0.0.1'],
  },
  {
    name: 'san with localhost dns',
    san: ['DNS:localhost'],
  },
  {
    name: 'san with unusual domain',
    san: ['DNS:node.localdomain.local'],
  },
  {
    name: 'san with internal only dns',
    san: ['DNS:internal.cluster.local'],
  },
  {
    name: 'san with ipv6 localhost',
    san: ['IP:::1'],
  },
  {
    name: 'san with ipv6 example',
    san: ['IP:fe80::1ff:fe23:4567:890a'],
  },
  {
    name: 'san with space in dns',
    san: ['DNS:node name.local'],
  },
  {
    name: 'san with email address',
    san: ['email:user@example.com'],
  },
  {
    name: 'san with URI',
    san: ['URI:https://node.example.com'],
  },
  {
    name: 'san with RID',
    san: ['RID:1.2.3.4.5'],
  },
  {
    name: 'san with otherName',
    san: ['otherName:1.2.3.4;UTF8:user'],
  },
]

beforeAll(() => {
  createDirectoryIfNotExists(outputDir)
})

afterAll(() => {
  removeDirectory(outputDir)
})

describe('[CSR denied]', () => {
  describe.each(sanList)
    ('[when Subject Alternative Names equal "$name"]', ({ name, san }) => {
      test('should prepare openssl files', async () => {
        // Subject
        const subject = [
          `CN=system:bootstrap:${nodeData.nodeName}`,
          `O=system:bootstrappers`,
          `O=system:bootstrappers:kubeadm:default-node-token`,
        ]

        // Subject Alternative Names
        const sanList = san

        // Генерируем ключи, конфиги, CSR и сертификат для клиента
        generateKeys(testFiles.privateKey, testFiles.publicKey)
        createExtFile(testFiles.ext, sanList)
        generateCSR(testFiles.privateKey, testFiles.csr, subject, sanList)
        signCertificate(testFiles.csr, testFiles.crt, kubeAuthFiles.caCrt, kubeAuthFiles.caKey, testFiles.ext)

        // Проверки
        expect(fs.existsSync(testFiles.privateKey)).toBe(true)
        expect(fs.existsSync(testFiles.publicKey)).toBe(true)
        expect(fs.existsSync(testFiles.ext)).toBe(true)
        expect(fs.existsSync(testFiles.csr)).toBe(true)
        expect(fs.existsSync(testFiles.crt)).toBe(true)
      })

      test('should create CSR', async () => {
        // Настройка HTTPS агента с mTLS
        const httpsAgent = new https.Agent({
          cert: fs.readFileSync(testFiles.crt),
          key: fs.readFileSync(testFiles.privateKey),
          ca: fs.readFileSync(kubeAuthFiles.caCrt),
          rejectUnauthorized: false,
        })

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
            usages: [
              "digital signature",
              "client auth"
            ],
          }
        }

        // Запрос
        const res = await fetch(`${baseURL}${csrPath}`, {
          method: 'POST',
          body: JSON.stringify(certificateSigningRequest),
          headers: { 'Content-Type': 'application/json' },
          agent: httpsAgent,
        })
        const body = await res.json()

        // Проверки
        expect(res.status).toBe(201)
        expect(body.metadata.name).toBe(csrName)
      })

      test('should deny CSR', async () => {
        // Настройка HTTPS агента с mTLS
        const httpsAgent = new https.Agent({
          cert: fs.readFileSync(testFiles.crt),
          key: fs.readFileSync(testFiles.privateKey),
          ca: fs.readFileSync(kubeAuthFiles.caCrt),
          rejectUnauthorized: false,
        })

        // Максимальное время ожидания
        const maxRetryTime = 60000
        const retryInterval = 5000
        const startTime = Date.now()
        const expectedStatus = 'Denied'

        // Цикл запросов
        while (Date.now() - startTime < maxRetryTime) {
          const res = await fetch(`${baseURL}${csrPath}/${csrName}`, {
            method: 'GET',
            agent: httpsAgent,
          })

          const body = await res.json()
          const lastStatus = body.status?.conditions?.[0]?.type || ''

          if (res.status === 200 && lastStatus === expectedStatus) {
            // Успешный случай
            expect(res.status).toBe(200)
            expect(body.metadata.name).toBe(csrName)
            expect(body.status.conditions[0].type).toBe(expectedStatus)
            return
          }

          // Ждём перед следующим запросом
          await new Promise(resolve => setTimeout(resolve, retryInterval))
        }

        // Если дошли сюда - значит Approved не получен за отведённое время
        throw new Error(`Timeout waiting for CSR "${csrName}" to have status "${expectedStatus}" within ${maxRetryTime / 1000} seconds`)
      })

      test('should delete CSR', async () => {
        // Настройка HTTPS агента с mTLS (для удаления CSR после тестов используем доступы от основного клиента)
        const httpsAgent = new https.Agent({
          cert: fs.readFileSync(kubeAuthFiles.clientCert),
          key: fs.readFileSync(kubeAuthFiles.clientKey),
          ca: fs.readFileSync(kubeAuthFiles.caCrt),
          rejectUnauthorized: false,
        })

        // Запрос на удаление
        const res = await fetch(`${baseURL}${csrPath}/${csrName}`, {
          method: 'DELETE',
          agent: httpsAgent,
        })
        const body = await res.json()

        // Проверки
        expect(res.status).toBe(200)
        expect(body.status).toBe('Success')
        expect(body.details.name).toBe(csrName)
      })
    })
})
