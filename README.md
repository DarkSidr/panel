# 3x-ui + nginx для Debian 13

Установка панели 3x-ui, HTTPS, подписок и firewall одной командой.
Новые VLESS-входы автоматически настраиваются после сохранения в панели.

## Требования

- Чистый Debian 13, amd64 или arm64, доступ root.
- Два разных домена: для сайта и панели. Все A/AAAA должны указывать на VPS.
- Открытые TCP 80 и 443; DNS без CDN proxy.

Существующие nginx, 3x-ui и сторонние firewall-конфигурации не перезаписываются.

## Установка

Подставьте свои домены и почту, выполните на VPS от root:

```sh
curl -fL https://raw.githubusercontent.com/DarkSidr/panel/main/install.sh -o /tmp/proxy-install.sh
sh /tmp/proxy-install.sh install --site example.org --panel panel.example.org --email admin@example.org
```

Загрузчик скачивает исходники с GitHub; git на сервере не нужен.
Параметр `--email` необязателен. Перед сообщением об успешной установке проверяются
службы, firewall, работа Xray и HTTPS сайта и панели.

Адрес панели, логин и пароль:

```sh
cat /etc/proxy-stack/credentials
```

На корне обоих доменов открывается сайт-заглушка.
Для входа в панель открывайте полный `URL` из этого файла, включая случайный путь.
После входа включите 2FA в настройках панели.

## Добавление подключений

1. Создайте VLESS-вход и клиента в панели, выберите транспорт.
2. Сохраните и дождитесь синхронизации — до 15 секунд.
3. Обновите страницу, затем скопируйте ссылку или подписку клиента.

RAW/TCP, XHTTP и gRPC получают REALITY; WebSocket и HTTPUpgrade — TLS через nginx.
Если TCP 443 уже занят другим REALITY-входом, автоматически выбирается дополнительный
публичный порт. Учётные данные и квоты клиентов сохраняются.

Для XHTTP/gRPC с обычным TLS добавьте `[TLS]` в примечание до первого сохранения.
Пометка `[MANUAL]` отключает автонастройку нового входа.
Другие протоколы и AmneziaWG требуют настройки по [инструкции](docs/INBOUNDS.md).

## Обслуживание

```sh
python3 /opt/proxy-stack/proxyctl.py doctor
python3 /opt/proxy-stack/proxyctl.py status
python3 /opt/proxy-stack/proxyctl.py backup
python3 /opt/proxy-stack/proxyctl.py update
```

Обновляйте панель через `proxyctl.py update`: команда сохраняет резервную копию.

Если настройки входа не применились:

```sh
python3 /opt/proxy-stack/proxyctl.py sync
journalctl -u proxy-stack-sync.service -n 30
```

Дополнительно: [входы и подписки](docs/INBOUNDS.md),
[проверки](docs/VALIDATION.md), [безопасность](docs/SECURITY.md).

## Удаление

```sh
python3 /opt/proxy-stack/proxyctl.py uninstall
```

Резервные копии остаются в `/var/lib/proxy-stack`.
Для удаления вместе с резервными копиями и секретами используйте `purge` вместо `uninstall`.
