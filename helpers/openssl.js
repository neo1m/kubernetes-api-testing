const fs = require('fs')
const { execSync } = require('child_process')

/**
 * Генерирует пару RSA-ключей: приватный и публичный.
 *
 * @param {string} privateKeyPath - Путь для сохранения приватного ключа.
 * @param {string} publicKeyPath - Путь для сохранения публичного ключа.
 */
function generateKeys(privateKeyPath, publicKeyPath) {
    // Команда для генерации приватного ключа
    const genPrivateKeyCmd = [
        'openssl', 'genpkey',
        '-algorithm', 'RSA',
        '-out', privateKeyPath,
        '-pkeyopt', 'rsa_keygen_bits:2048'
    ].join(' ')

    execSync(genPrivateKeyCmd, { stdio: 'ignore' })

    // Команда для извлечения публичного ключа
    const extractPublicKeyCmd = [
        'openssl', 'rsa',
        '-in', privateKeyPath,
        '-pubout',
        '-out', publicKeyPath
    ].join(' ')

    execSync(extractPublicKeyCmd, { stdio: 'ignore' })
}

/**
 * Генерирует CSR (запрос на сертификат) на основе приватного ключа и конфигурационного файла.
 *
 * @param {string} privateKeyPath - Путь к приватному ключу (например, './key.pem').
 * @param {string} csrPath - Путь для сохранения CSR файла (например, './cert.csr').
 * @param {string[]} subject - Массив компонентов Subject (например ["O=system:bootstrapers", "CN=myuser"])
 * @param {string[]} [san=[]] - Массив SAN (например ["DNS:example.com"])
 */
function generateCSR(privateKeyPath, csrPath, subject, san = []) {
    // Формируем строку Subject
    const subjectStr = subject.join('/')

    // Аргументы команды
    const args = [
        'openssl', 'req',
        '-new',
        '-key', privateKeyPath,
        '-out', csrPath,
        '-subj', `"/${subjectStr}"`
    ]

    // Добавляем SAN если есть
    if (san && san.length > 0) {
        args.push('-addext', `"subjectAltName=${san.join(',')}"`)
    }

    // Собираем команду OpenSSL
    const command = args.join(' ')

    execSync(command, { stdio: 'ignore' })
}

/**
 * Кодирует CSR-файл в base64.
 * @param {string} csrPath - Путь к .csr файлу.
 * @returns {string} CSR в base64.
 */
function encodeCSRToBase64(csrPath) {
    const csrBuffer = fs.readFileSync(csrPath)
    return csrBuffer.toString('base64').replace(/\r?\n/g, '')
}

/**
 * Создаёт временный конфигурационный файл расширений для подписания сертификата (X.509).
 * Включает SAN (Subject Alternative Names).
 *
 * @param {string} extPath - Путь для сохранения расширенного конфигурационного файла (например, './ext.cnf').
 * @param {string[]} sanList - Список SAN-значений, например: ['DNS:example.com', 'DNS:www.example.com'].
 */
function createExtFile(extPath, sanList) {
    const extContent = [
        `subjectAltName = ${sanList.join(',')}`,
    ].join('\n')
    fs.writeFileSync(extPath, extContent)
}

/**
 * Подписывает CSR-файл и создаёт SSL-сертификат с использованием CA-сертификата и CA-ключа.
 *
 * @param {string} csrPath - Путь к входному CSR файлу (например, './request.csr').
 * @param {string} certPath - Путь для сохранения сгенерированного сертификата (например, './cert.crt').
 * @param {string} caCertPath - Путь к CA-сертификату (например, './ca.crt').
 * @param {string} caKeyPath - Путь к приватному ключу CA (например, './ca.key').
 * @param {string} extPath - Путь к конфигурационному файлу расширений (например, './ext.cnf').
 */
function signCertificate(csrPath, certPath, caCertPath, caKeyPath, extPath = null) {
    // Аргументы команды
    const args = [
        'openssl', 'x509',
        '-req',
        '-in', csrPath,
        '-CA', caCertPath,
        '-CAkey', caKeyPath,
        '-CAcreateserial',
        '-out', certPath,
        '-days', '365',
        '-sha256'
    ]

    // Добавляем extentions если есть
    if (extPath) {
        args.push('-extfile', extPath)
    }

    // Собираем команду OpenSSL
    const command = args.join(' ')

    execSync(command, { stdio: 'ignore' })
}

module.exports = {
    generateKeys,
    generateCSR,
    encodeCSRToBase64,
    createExtFile,
    signCertificate,
}
