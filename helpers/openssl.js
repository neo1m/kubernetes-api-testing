const { execSync } = require('child_process')
const fs = require('fs')

/**
 * Генерирует пару RSA-ключей: приватный и публичный.
 *
 * @param {string} privateKeyPath - Путь для сохранения приватного ключа.
 * @param {string} publicKeyPath - Путь для сохранения публичного ключа.
 */
function generateKeys(privateKeyPath, publicKeyPath) {
    // Генерация приватного ключа
    execSync(`
        openssl genpkey \
        -algorithm RSA \
        -out ${privateKeyPath} \
        -pkeyopt rsa_keygen_bits:2048
    `, { stdio: 'ignore' })

    // Извлечение публичного ключа из приватного
    execSync(`
        openssl rsa \
        -in ${privateKeyPath} \
        -pubout \
        -out ${publicKeyPath}
    `, { stdio: 'ignore' })
}

/**
 * Генерирует CSR (запрос на сертификат) на основе приватного ключа и конфигурационного файла.
 *
 * @param {string} privateKeyPath - Путь к приватному ключу (например, './key.pem').
 * @param {string} csrPath - Путь для сохранения CSR файла (например, './cert.csr').
 * @param {string} configPath - Путь к конфигурационному файлу OpenSSL (например, './csr_config.cnf').
 */
function generateCSR(privateKeyPath, csrPath, configPath) {
    execSync(`
        openssl req \
        -new \
        -key ${privateKeyPath} \
        -out ${csrPath} \
        -config "${configPath}"
    `, { stdio: 'ignore' })
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
 * Генерирует временный конфигурационный файл для CSR с SAN.
 * @param {string} configPath - Пример: "CN=example.com,O=MyOrg,C=US"
 * @param {string} subject - Пример: "CN=example.com,O=MyOrg,C=US"
 * @param {string[]} sanList - Пример: ["DNS:example.com", "DNS:www.example.com"]
 * @returns {string} путь к созданному файлу
 */
function createCnfFile(configPath, subject, sanList = []) {
    const dnSection = subject
        .split(',')
        .map(entry => {
            const [key, value] = entry.split('=')
            return `${key.trim()} = ${value.trim()}`
        })
        .join('\n')

    const sanLine = sanList.length > 0
        ? `subjectAltName = ${sanList.join(',')}`
        : ''

    const lines = [
        '[ req ]',
        'default_bits       = 2048',
        'prompt             = no',
        'default_md         = sha256',
        'distinguished_name = dn',
        'req_extensions     = req_ext',
        '',
        '[ dn ]',
        dnSection,
        '',
        '[ req_ext ]',
        sanLine
    ]

    const configContent = lines
        .filter(line => line.trim() !== '')
        .join('\n')

    fs.writeFileSync(configPath, configContent)
}

/**
 * Создаёт временный конфигурационный файл расширений для подписания сертификата (X.509).
 * Включает SAN (Subject Alternative Names) и базовые настройки.
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
function signCertificate(csrPath, certPath, caCertPath, caKeyPath, extPath) {
    execSync(`
        openssl x509 \
        -req \
        -in ${csrPath} \
        -CA ${caCertPath} \
        -CAkey ${caKeyPath} \
        -CAcreateserial \
        -out ${certPath} \
        -days 365 \
        -sha256 \
        -extfile ${extPath}
    `, { stdio: 'ignore' })
}

module.exports = {
    generateKeys,
    generateCSR,
    encodeCSRToBase64,
    createCnfFile,
    createExtFile,
    signCertificate,
}
