const { getNode } = require('#helpers/nodeHelpers.js')

/**
 * Метод для получения информации о Node до тех пор,
 * пока не будет возвращен код 200 и установлены ExternalIP и InternalIP.
 *
 * @param {string} nodeName - Имя узла (Node), который нужно проверить.
 * @param {number} timeoutMs - Максимальное время ожидания в миллисекундах.
 * @param {number} intervalMs - Интервал между запросами в миллисекундах.
 * @returns {Promise<{ status: number, body: object }>} - Информация о Node после успешного получения данных.
 */
async function waitForNodeReadiness(nodeName, timeoutMs = 30000, intervalMs = 5000) {
    const deadline = Date.now() + timeoutMs

    while (Date.now() < deadline) {
        const { status, body } = await getNode(nodeName)

        if (status === 200) {
            const addresses = body?.status?.addresses || []
            const hasExternalIP = addresses.some((a) => a.type === 'ExternalIP')
            const hasInternalIP = addresses.some((a) => a.type === 'InternalIP')

            if (hasExternalIP && hasInternalIP) {
                return { status, body }
            }
        }

        await new Promise(resolve => setTimeout(resolve, intervalMs))
    }

    throw new Error(`Timeout waiting for Node "${nodeName}" to have ExternalIP and InternalIP within ${timeoutMs / 1000} seconds`)
}

module.exports = { waitForNodeReadiness }
