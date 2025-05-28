# Проверка CSR (запросов на подпись сертификата)

## Серверный CSR

### Subject

* `O`: только

  * `system:nodes`

* `CN`: `system:node:<machineName>`

### Subject Alternative Name (SAN)

* `IP`: только внутренний и внешний IP ноды, либо loopback IP либо все три вместе

  * `IP:externalIP`
  * `IP:internalIP`
  * `IP:127.0.0.1`

### Поля `spec`

* `groups`: как минимум одно значение из указанных (порядок не важен)

  * `system:nodes`
  * `system:authenticated`

* `usages`: как минимум одно значение из указанных (порядок не важен)

  * `digital signature`
  * `server auth`

* `username`: `system:node:<machineName>`


## Клиентский CSR

### Subject

* `O`: только

  * `system:bootstrappers`
  * `system:bootstrappers:kubeadm:default-node-token`

* `CN`: `system:bootstrap:<machineName>`

### Subject Alternative Name (SAN)

* **SAN не должен присутствовать**

### Поля `spec`

* `groups`: как минимум одно значение из указанных (порядок не важен)

  * `system:bootstrappers`
  * `system:bootstrappers:kubeadm:default-node-token`
  * `system:authenticated`

* `usages`: как минимум одно значение из указанных (порядок не важен)

  * `digital signature`
  * `client auth`

* `username`: `system:bootstrap:<machineName>`
