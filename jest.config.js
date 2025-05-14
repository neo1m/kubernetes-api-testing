module.exports = {
  // Показывать описание тестов
  verbose: true,

  // Максимальное время выполнения теста
  testTimeout: 120000,

  // Количество потоков выполнения тестов
  maxWorkers: 1,

  // Вспомогательный код для тестов
  setupFilesAfterEnv: ['./jest.setup.js'],

  // Игнорирование файлов и директорий
  testPathIgnorePatterns: [
    "/node_modules/", // Игнорируем директорию node_modules
    "/old-tests/", // Игнорируем директорию old-tests
    ".*\\.skip\\.test\\.js$", // Игнорируем файлы с суффиксом .skip.test.js
    ".*disabled.*\\.test\\.js$", // Игнорировать файлы с "disabled" в имени
  ],
}