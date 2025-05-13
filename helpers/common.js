const fs = require('fs')

// Функция для создания директории, если её нет
function createDirectoryIfNotExists(dirPath) {
    if (!fs.existsSync(dirPath)) {
        console.log(`Директория не существует. Создание: ${dirPath}`)
        fs.mkdirSync(dirPath, { recursive: true }) // Создание директории (с поддержкой рекурсии)
    } else {
        console.log(`Директория уже существует: ${dirPath}`)
    }
}

// Функция для удаления директории
function removeDirectory(dirPath) {
    if (fs.existsSync(dirPath)) {
        console.log(`Удаление директории: ${dirPath}`)
        fs.rmSync(dirPath, { recursive: true, force: true }) // Удаление директории (с поддержкой рекурсии)
    } else {
        console.log(`Директория не существует: ${dirPath}`)
    }
}

module.exports = {
    createDirectoryIfNotExists,
    removeDirectory,
}