const fs = require('fs')
const path = require('path')
const fetch = require('node-fetch')

// Базовый конфиг
const { outputDir, kubeAuthFiles, kube } = require('#root/config.js')

// Тестовые данные
const { csrTests } = require('#fixtures/common-test-data.js')

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
  createExtFile,
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
const csrName = csrTests.serverCSRName
const nodeData = csrTests.nodeData

// Для данных spec.groups запрещено создание CSR
const csrCreationForbiddenGroups = [
  {
    name: 'empty group list',
    groups: [],
  },
  {
    name: 'similar group name (system:node)',
    groups: ['system:node'],
  },
  {
    name: 'typo in group name',
    groups: ['system:nodez'],
  },
  {
    name: 'group with prefix',
    groups: ['extra:system:nodes'],
  },
  {
    name: 'both groups in one string',
    groups: ['system:nodes system:bootstrappers'],
  },
  {
    name: 'system:nodes with suffix',
    groups: ['system:nodes:worker'],
  },
  {
    name: 'uppercase group name',
    groups: ['SYSTEM:NODES'],
  },
  {
    name: 'whitespace-only group',
    groups: [' '],
  },
  {
    name: 'numeric group name',
    groups: ['12345'],
  },
  {
    name: 'group with invalid characters',
    groups: ['system:nodes$', 'admin'],
  },
  {
    name: 'boolean as group name',
    groups: [true],
  },
  {
    name: 'object instead of string',
    groups: [{}],
  },
  {
    name: 'undefined in group list',
    groups: [undefined],
  },
  {
    name: 'system:bootstrappers only',
    groups: ['system:bootstrappers'],
  },
  {
    name: 'system:authenticated only',
    groups: ['system:authenticated'],
  },
  {
    name: 'system:unauthenticated only',
    groups: ['system:unauthenticated'],
  },
  {
    name: 'multiple unrelated controllers',
    groups: ['system:controller:cronjob-controller', 'system:controller:statefulset-controller'],
  },
  {
    name: 'controller and serviceaccounts mix',
    groups: ['system:controller:job-controller', 'system:serviceaccounts'],
  },
  {
    name: 'node-controller with serviceaccounts',
    groups: ['system:controller:node-controller', 'system:serviceaccounts:kube-system'],
  },
  {
    name: 'system:serviceaccounts only',
    groups: ['system:serviceaccounts'],
  },
  {
    name: 'system:serviceaccounts with namespace',
    groups: ['system:serviceaccounts:my-namespace'],
  },
  {
    name: 'system:kube-proxy only',
    groups: ['system:kube-proxy'],
  },
  {
    name: 'system:controller:node-controller only',
    groups: ['system:controller:node-controller'],
  },
  {
    name: 'system:controller:deployment-controller only',
    groups: ['system:controller:deployment-controller'],
  },
  {
    name: 'system:controller:endpoint-controller only',
    groups: ['system:controller:endpoint-controller'],
  },
]

// Для данных spec.groups отклоняется созданный CSR
const csrDeniedGroups = [
  {
    name: 'system:nodes + extra group',
    groups: ['system:nodes', 'extra:group'],
  },
  {
    name: 'required groups plus one extra (system:masters)',
    groups: ['system:nodes', 'system:masters'],
  },
  {
    name: 'unrelated bootstrap groups',
    groups: ['system:bootstrappers', 'system:bootstrappers:kubeadm:default-node-token'],
  },
  {
    name: 'duplicate system:nodes group',
    groups: ['system:nodes', 'system:nodes'],
  },
  {
    name: 'system:nodes with system:bootstrappers',
    groups: ['system:nodes', 'system:bootstrappers'],
  },
  {
    name: 'system:masters only',
    groups: ['system:masters'],
  },
  {
    name: 'system:nodes + system:authenticated',
    groups: ['system:nodes', 'system:authenticated'],
  },
  {
    name: 'system:nodes + system:unauthenticated',
    groups: ['system:nodes', 'system:unauthenticated'],
  },
  {
    name: 'system:nodes duplicated',
    groups: ['system:nodes', 'system:nodes'],
  },
  {
    name: 'system:nodes with kube-controller-manager',
    groups: ['system:nodes', 'system:kube-controller-manager'],
  },
  {
    name: 'system:nodes with controller groups',
    groups: ['system:nodes', 'system:controller:replicaset-controller'],
  },
  {
    name: 'system:nodes with lowercase and uppercase variant',
    groups: ['system:nodes', 'System:Nodes'],
  },
]

beforeAll(() => {
  createDirectoryIfNotExists(outputDir)
})

afterAll(() => {
  removeDirectory(outputDir)
})

describe('[CSR denied]', () => {
  describe.each([
    ...csrCreationForbiddenGroups,
    ...csrDeniedGroups,
  ])
    ('[when Subject Common Name in CSR equal "$name"]', ({ name, groups }) => {
      test('should prepare openssl files', async () => {
        // Преобразуем массив к формату для генерации CSR
        const formatGroups = groups.map((group) => `O=${group}`)

        // Subject
        const subject = [
          `CN=system:node:${nodeData.nodeName}`,
          ...formatGroups,
        ]

        // Subject Alternative Names
        const sanList = [
          `IP:${nodeData.externalIP}`,
          `IP:${nodeData.internalIP}`,
        ]

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
            signerName: "kubernetes.io/kubelet-serving",
            usages: [
              "digital signature",
              "server auth"
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

        // Запрос на удаление
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
