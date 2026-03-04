# slipstream-server-installer

نصب و مدیریت سریع **slipstream-server** روی سرور خارج.

---

## نصب

```bash
curl -sSL https://raw.githubusercontent.com/alisamani1378/slipstream-server-installer/main/install.sh | sudo bash
```

اسکریپت:
1. باینری سرور را دانلود و نصب می‌کند
2. اطلاعات لازم را می‌پرسد (domain, target address, port, cert/key)
3. اگر certificate نداشته باشید، خودکار یک self-signed cert می‌سازد
4. سرویس systemd ایجاد و فعال می‌کند

---

## مدیریت

بعد از نصب، با دستور `slipstream` سرور را مدیریت کنید:

| دستور | توضیح |
|---|---|
| `slipstream status` | وضعیت سرویس |
| `slipstream start` | شروع سرویس |
| `slipstream stop` | توقف سرویس |
| `slipstream restart` | ریستارت سرویس |
| `slipstream logs` | مشاهده لاگ (زنده) |
| `slipstream edit` | ویرایش تنظیمات (domain, target, port, cert, key) |
| `slipstream uninstall` | حذف کامل |

---

## تنظیمات

فایل کانفیگ بعد از نصب اینجاست:

```
/etc/slipstream/server.conf
```

فایل سرویس systemd:

```
/etc/systemd/system/slipstream-server.service
```

برای تغییر تنظیمات:

```bash
nano /etc/systemd/system/slipstream-server.service
systemctl daemon-reload
slipstream restart
```

---

## پیش‌نیازها

- سیستم‌عامل: **Linux (Ubuntu/Debian) — AMD64**
- دسترسی: **root**
- پورت‌ها: **UDP 53** (یا پورت دلخواه DNS) باید باز باشد

---

## نصب کلاینت روی سرور ایران

برای نصب کلاینت روی سرورهای ایران، اسکریپت و باینری کلاینت را روی یک وب‌سرور ایرانی قرار دهید (چون دسترسی به GitHub محدود است).

روی وب‌سرور ایران:

```bash
mkdir -p /var/www/slipstream

# فایل‌ها را از سرور بیلد کپی کنید:
# - slipstream-client  (باینری)
# - install-client.sh  (اسکریپت نصب)

cd /var/www/slipstream
python3 -m http.server 8443 --bind 0.0.0.0
```

روی هر سرور ایرانی:

```bash
curl -sSL http://IP_WEBSERVER:8443/install-client.sh | sudo bash
```
