const fs = require('fs')

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

module.exports = {
    createDirectoryIfNotExists,
    removeDirectory,
}