const fs = require('fs')
const https = require('https')

// Функция для создания директории, если её нет
function createDirectoryIfNotExists(dirPath) {
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true })
    }
}

// Функция для удаления директории
function removeDirectory(dirPath) {
    if (fs.existsSync(dirPath)) {
        fs.rmSync(dirPath, { recursive: true, force: true })
    }
}

// Функция для создания файла, если его нет
function createFileIfNotExists(filePath, content = '') {
    if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, content)
    }
}

// Функция для удаления файла
function removeFile(filePath) {
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath)
    }
}

// Создаёт HTTPS-агент
function createHttpsAgent(certPath, keyPath, caPath) {
    return new https.Agent({
        cert: fs.readFileSync(certPath),
        key: fs.readFileSync(keyPath),
        ca: fs.readFileSync(caPath),
        rejectUnauthorized: false,
    })
}

module.exports = {
    createDirectoryIfNotExists,
    removeDirectory,
    createFileIfNotExists,
    removeFile,
    createHttpsAgent,
}
