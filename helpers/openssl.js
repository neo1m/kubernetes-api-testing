const { execSync } = require('child_process')
const fs = require('fs')

function generateKey(privateKeyPath, publicKeyPath) {
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

function generateCSR(privateKeyPath, csrPath, subject) {
    const subjString = '/' + subject.replace(/,/g, '/')
    execSync(`
        openssl req \
        -new \
        -key ${privateKeyPath} \
        -out ${csrPath} \
        -subj "${subjString}"
    `)
}

function createExtFile(extPath, sanList) {
    const extContent = [
        'basicConstraints=CA:FALSE',
        'keyUsage = digitalSignature, keyEncipherment',
        `subjectAltName = ${sanList.join(',')}`,
    ].join('\n');
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
    generateKey,
    generateCSR,
    createExtFile,
    signCertificate,
}
