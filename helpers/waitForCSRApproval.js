const { getCSR } = require('#helpers/csrHelpers.js')

/**
 * Ожидает определённый статус CSR.
 *
 * @param {string} csrName - Имя CSR.
 * @param {string} expectedStatus - Ожидаемый статус (например, "Approved", "Denied").
 * @param {number} timeoutMs - Максимальное время ожидания в миллисекундах.
 * @param {number} intervalMs - Интервал между запросами в миллисекундах.
 * @returns {Promise<{ status: number, body: object }>} - Возвращает результат последнего запроса.
 */
async function waitForCSRStatus(csrName, expectedStatus, timeoutMs = 30000, intervalMs = 5000) {
    const deadline = Date.now() + timeoutMs

    while (Date.now() < deadline) {
        const { status, body } = await getCSR(csrName)

        if (status === 200) {
            const conditions = body?.status?.conditions || []

            if (Array.isArray(conditions)) {
                const matchingCondition = conditions.find(c => c.type === expectedStatus && c.status === 'True')

                if (matchingCondition) {
                    return { status, body }
                }
            }
        }

        await new Promise(resolve => setTimeout(resolve, intervalMs))
    }

    throw new Error(`Timeout waiting for CSR "${csrName}" to have status "${expectedStatus}" within ${timeoutMs / 1000} seconds`)
}

module.exports = { waitForCSRStatus }
