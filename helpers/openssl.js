const { execSync } = require('child_process')
const fs = require('fs')

function generateKeys(privateKeyPath, publicKeyPath) {
    // 1. Генерация приватного ключа
    execSync(`
        openssl genpkey \
        -algorithm RSA \
        -out ${privateKeyPath} \
        -pkeyopt rsa_keygen_bits:2048
    `)

    // 2. Извлечение публичного ключа из приватного
    execSync(`
        openssl rsa \
        -in ${privateKeyPath} \
        -pubout \
        -out ${publicKeyPath}
    `)
}

function generateCSR(privateKeyPath, csrPath, configPath) {
    execSync(`
        openssl req \
        -new \
        -key ${privateKeyPath} \
        -out ${csrPath} \
        -config "${configPath}"
    `)
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

function createExtFile(extPath, sanList) {
    const extContent = [
        'basicConstraints=CA:FALSE',
        'keyUsage = digitalSignature, keyEncipherment',
        `subjectAltName = ${sanList.join(',')}`,
    ].join('\n')
    fs.writeFileSync(extPath, extContent)
}

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
    `)
}

module.exports = {
    generateKeys,
    generateCSR,
    encodeCSRToBase64,
    createCnfFile,
    createExtFile,
    signCertificate,
}
