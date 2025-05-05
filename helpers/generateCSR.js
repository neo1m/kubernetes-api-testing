const forge = require('node-forge')

/**
 * Генерация CSR запроса
 * @param {Object} options - Настройки для генерации
 * @param {string} options.commonName - Common Name (CN)
 * @param {string} options.countryName - Страна (C)
 * @param {string} options.stateName - Штат/регион (ST)
 * @param {string} options.localityName - Город (L)
 * @param {string} options.organizationName - Организация (O)
 * @param {string} options.organizationalUnitName - Подразделение (OU)
 * @param {string} options.emailAddress - Email адрес
 * @param {string[]} options.altNames - Список SAN (альтернативные имена)
 * @returns {Object} { csrPem, csrBase64 }
 */
function generateCSR(options) {
  const keys = forge.pki.rsa.generateKeyPair(2048)
  const csr = forge.pki.createCertificationRequest()

  csr.publicKey = keys.publicKey

  // Динамическая сборка subject
  const subjectFields = []

  if (options.commonName) {
    subjectFields.push({ name: 'commonName', value: options.commonName })
  }
  if (options.countryName) {
    subjectFields.push({ name: 'countryName', value: options.countryName })
  }
  if (options.stateName) {
    subjectFields.push({ name: 'stateOrProvinceName', value: options.stateName })
  }
  if (options.localityName) {
    subjectFields.push({ name: 'localityName', value: options.localityName })
  }
  if (options.organizationName) {
    subjectFields.push({ name: 'organizationName', value: options.organizationName })
  }
  if (options.organizationalUnitName) {
    subjectFields.push({ name: 'organizationalUnitName', value: options.organizationalUnitName })
  }
  if (options.emailAddress) {
    subjectFields.push({ name: 'emailAddress', value: options.emailAddress })
  }

  csr.setSubject(subjectFields)

  // Добавляем SAN (если есть)
  if (options.altNames && options.altNames.length > 0) {
    const altNamesExtensions = options.altNames.map(({ type, value }) => {
      switch (type) {
        case 'dns': return { type: 2, value }
        case 'ip': return { type: 7, ip: value }
        case 'email': return { type: 1, value }
        case 'uri': return { type: 6, value }
        default: return null
      }
    }).filter(Boolean)

    csr.setAttributes([
      {
        name: 'extensionRequest',
        extensions: [
          {
            name: 'subjectAltName',
            altNames: altNamesExtensions
          }
        ]
      }
    ])
  }

  csr.sign(keys.privateKey)

  const pem = forge.pki.certificationRequestToPem(csr)
  const base64 = Buffer.from(pem).toString('base64').replace(/\r?\n/g, '')

  return {
    csrPem: pem,
    csrBase64: base64,
  }
}

module.exports = {
  generateCSR,
}
