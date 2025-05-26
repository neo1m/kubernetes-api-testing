# Проверка CSR (запросов на подпись сертификата)

## Серверный CSR

### Subject

* `O`: строго `system:nodes`
* `CN`: `system:node:<machineName>`

### Subject Alternative Name (SAN)

* IP-адреса: соответствуют внутреннему и внешнему IP ноды
* DNS-имена (если есть): содержат `<machineName>`

### Поля `spec`

* `groups`:

  * `system:nodes`
  * `system:authenticated`
* `usages`:

  * `digital signature`
  * `server auth`
* `username`: `system:node:<machineName>`


## Клиентский CSR

### Subject

* `O`: только

  * `system:bootstrappers`
  * `system:bootstrappers:kubeadm:default-node-token`
  * `system:authenticated`
* `CN`: `system:bootstrap:<machineName>`

### Subject Alternative Name (SAN)

* **SAN не должен присутствовать**

### Поля `spec`

* `groups`:

  * `system:bootstrappers`
  * `system:bootstrappers:kubeadm:default-node-token`
  * `system:authenticated`
* `usages`:

  * `digital signature`
  * `client auth`
* `username`: `system:bootstrap:<machineName>`
