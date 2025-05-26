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
  createExtFile,
  signCertificate,
} = require('#helpers/openssl.js')

// Адрес API
const baseURL = `https://${kube.host}:${kube.port}`
const csrPath = '/apis/certificates.k8s.io/v1/certificatesigningrequests'

// Тестовые данные
const csrName = csrTests.serverCSRName
const nodeData = csrTests.nodeData

// Для данных Subject Common Name запрещено создание CSR
const csrCreationForbiddenCommonNames = [
  {
    name: 'random string identifier',
    cn: ['qwerty123']
  },
  {
    name: 'bootstrap with client node name',
    cn: [`system:bootstrap:${nodeData.nodeName}`]
  },
  {
    name: 'system anonymous',
    cn: ['system:anonymous']
  },
  {
    name: 'system unauthenticated',
    cn: ['system:unauthenticated']
  },
  {
    name: 'system authenticated',
    cn: ['system:authenticated']
  },
  {
    name: 'public info viewer',
    cn: ['system:public-info-viewer']
  },
  {
    name: 'kube proxy',
    cn: ['system:kube-proxy']
  },
  {
    name: 'kube controller manager',
    cn: ['system:kube-controller-manager']
  },
  {
    name: 'kube scheduler',
    cn: ['system:kube-scheduler']
  },
  {
    name: 'bootstrappers',
    cn: ['system:bootstrappers']
  },
  {
    name: 'nodes group',
    cn: ['system:nodes']
  },
  {
    name: 'masters group',
    cn: ['system:masters']
  },
  {
    name: 'api server',
    cn: ['system:apiserver']
  },
  {
    name: 'volume scheduler',
    cn: ['system:volume-scheduler']
  },
  {
    name: 'node problem detector',
    cn: ['system:node-problem-detector']
  },
  {
    name: 'node node admin',
    cn: ['system:node:admin']
  },
  {
    name: 'admin',
    cn: ['admin']
  },
  {
    name: 'kubelet',
    cn: ['kubelet']
  },
  {
    name: 'bare kube-proxy',
    cn: ['kube-proxy']
  },
  {
    name: 'default serviceaccount',
    cn: ['system:serviceaccount:default:default']
  },
  {
    name: 'node controller',
    cn: ['system:controller:node-controller']
  },
  {
    name: 'deployment controller',
    cn: ['system:controller:deployment-controller']
  },
  {
    name: 'endpoint controller',
    cn: ['system:controller:endpoint-controller']
  },
  {
    name: 'replicaset controller',
    cn: ['system:controller:replicaset-controller']
  },
  {
    name: 'statefulset controller',
    cn: ['system:controller:statefulset-controller']
  },
  {
    name: 'job controller',
    cn: ['system:controller:job-controller']
  },
  {
    name: 'cronjob controller',
    cn: ['system:controller:cronjob-controller']
  },
  {
    name: 'daemonset controller',
    cn: ['system:controller:daemonset-controller']
  },
  {
    name: 'service controller',
    cn: ['system:controller:service-controller']
  },
  {
    name: 'namespace controller',
    cn: ['system:controller:namespace-controller']
  },
  {
    name: 'resourcequota controller',
    cn: ['system:controller:resourcequota-controller']
  },
  {
    name: 'horizontal pod autoscaler',
    cn: ['system:controller:horizontal-pod-autoscaler']
  },
  {
    name: 'certificate controller',
    cn: ['system:controller:certificate-controller']
  },
  {
    name: 'route controller',
    cn: ['system:controller:route-controller']
  },
  {
    name: 'null common name',
    cn: [null]
  },
  {
    name: 'undefined common name',
    cn: [undefined]
  },
  {
    name: 'whitespace only',
    cn: ['   ']
  },
  {
    name: 'multiple common names',
    cn: ['admin', 'system:authenticated']
  },
  {
    name: 'valid and invalid combined',
    cn: [`system:node:${nodeData.nodeName}`, 'admin']
  },
  {
    name: 'two identical invalid values',
    cn: ['system:authenticated', 'system:authenticated']
  },
  {
    name: 'null and undefined in cn',
    cn: [null, undefined]
  },
  {
    name: 'empty string and whitespace',
    cn: ['', '   ']
  },
  {
    name: 'number as common name',
    cn: ['12345']
  },
  {
    name: 'json in common name',
    cn: ['{"user":"node"}']
  },
  {
    name: 'multiple controllers',
    cn: ['system:controller:node-controller', 'system:controller:deployment-controller', 'system:controller:endpoint-controller']
  },
  {
    name: 'special ids combo',
    cn: ['system:kube-proxy', 'system:kube-controller-manager', 'system:kube-scheduler']
  },
  {
    name: 'single system anonymous',
    cn: ['system:anonymous']
  },
  {
    name: 'single admin',
    cn: ['admin']
  },
  {
    name: 'authenticated and unauthenticated',
    cn: ['system:authenticated', 'system:unauthenticated']
  },
  {
    name: 'repeated authenticated',
    cn: ['system:authenticated', 'system:authenticated']
  },
  {
    name: 'repeated node controller',
    cn: ['system:controller:node-controller', 'system:controller:node-controller']
  },
  {
    name: 'mixed admin and kubelet',
    cn: ['admin', 'kubelet']
  },
  {
    name: 'mixed special and controller',
    cn: ['system:bootstrappers', 'system:controller:deployment-controller']
  },
]

// Для данных Subject Common Name запрещено создание CSR
const csrCreationUnauthorizedCommonNames = [
  {
    name: 'empty common name array',
    cn: []
  },
  {
    name: 'empty string value',
    cn: ['']
  },
]

// Для данных Subject Common Name отклоняется созданный CSR
const csrDeniedCommonNames = [
  {
    name: 'duplicated valid pattern',
    cn: [`system:node:${nodeData.nodeName}`, `system:node:${nodeData.nodeName}`]
  },
  {
    name: 'duplicated invalid pattern',
    cn: [`system:bootstrap:${nodeData.nodeName}`, `system:bootstrap:${nodeData.nodeName}`]
  },
  {
    name: 'server and random common name',
    cn: [`system:node:${nodeData.nodeName}`, 'system:node:admin',]
  },
  {
    name: 'server and random common name reversed order',
    cn: ['system:node:admin', `system:node:${nodeData.nodeName}`]
  },
  {
    name: 'client and random common name',
    cn: ['system:node:admin', `system:bootstrap:${nodeData.nodeName}`]
  },
  {
    name: 'server and client common name',
    cn: [`system:bootstrap:${nodeData.nodeName}`, `system:node:${nodeData.nodeName}`]
  },
  {
    name: 'kube-system serviceaccount',
    cn: ['system:serviceaccount:kube-system:default']
  },
  {
    name: 'service accounts default and kube-system',
    cn: ['system:serviceaccount:default:default', 'system:serviceaccount:kube-system:default']
  },
]

beforeAll(() => {
  createDirectoryIfNotExists(outputDir)
})

describe('[CSR denied]', () => {
  describe.each([
    ...csrCreationForbiddenCommonNames,
    ...csrCreationUnauthorizedCommonNames,
    ...csrDeniedCommonNames,
  ])
    ('[when spec.username equal "$name"]', ({ name, cn }) => {
      // Директория и файлы для каждого тестового набора данных
      const fileName = path.basename(__filename, path.extname(__filename))
      const testCaseName = name.replace(/\s+/g, '_')
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
        // Преобразуем массив к формату для генерации CSR
        const formatCommonNames = cn.map((name) => `CN=${name}`)

        // Subject
        const subject = [
          ...formatCommonNames,
          `O=system:nodes`,
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
              "server auth",
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
