# آموزش راه‌اندازی پروژه (Cloudflare Worker + Google Apps Script)
| [English](README.md) | [Persian](README_FA.md) |
| :---: | :---: |

Persian translation was provided by [pingplas_channel](https://t.me/pingplas_channel)


---

## 1) نصب پیش‌نیازها
دستور زیر را اجرا کنید:

```bash
pip install -r requirements.txt
```

---

## 2) راه‌اندازی Cloudflare Worker (worker.js)

1. وارد داشبورد Cloudflare شوید و لاگین کنید.
2. از منوی کناری بروید به:
   **Compute > Workers & Pages**
3. روی **Create Application** کلیک کنید.
4. گزینه **Start with Hello World** را انتخاب کرده و Deploy کنید.
5. روی **Edit code** بزنید.
6. تمام کدهای پیش‌فرض را حذف کنید.
7. فایل `worker.js` پروژه (پوشه script) را باز کنید.
8. کل کد را کپی کرده و در ادیتور Cloudflare پیست کنید.

⚠️ مهم:
این خط را با آدرس ورکر خودتان جایگزین کنید:
```
const WORKER_URL = "myworker.workers.dev";
```

9. روی **Deploy** کلیک کنید.

---

## 3) راه‌اندازی Google Relay (Code.gs)

1. وارد Google Apps Script شوید.
2. روی **New Project** کلیک کنید.
3. تمام کدهای پیش‌فرض را حذف کنید.
4. فایل `Code.gs` پروژه را باز کرده و کپی کنید.
5. کد را داخل ادیتور پیست کنید.

⚠️ مهم:
```
const AUTH_KEY = "your-secret-password-here";
const WORKER_URL = "https://myworker.workers.dev";
```

- یک رمز دلخواه قوی انتخاب کنید.
- آدرس Worker خودتان را جایگزین کنید.

---

### Deploy کردن

1. از بالا روی **Deploy → New deployment** کلیک کنید.
2. نوع را روی **Web app** بگذارید.
3. تنظیمات:
   - Execute as: **Me**
   - Who has access: **Anyone**
4. روی **Deploy** بزنید.

📌 بعد از Deploy:
یک **Deployment ID** دریافت می‌کنید (رشته طولانی)
→ این را ذخیره کنید.

⚠️ رمز عبوری که انتخاب کردید را حتما نگه دارید.

---

## 4) تنظیم فایل config.json


سپس فایل `config.json` را باز کرده و مقادیر را وارد کنید:

```json
{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "PASTE_YOUR_DEPLOYMENT_ID_HERE",
  "auth_key": "your-secret-password-here",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "socks5_enabled": true,
  "socks5_port": 1080,
  "log_level": "INFO",
  "verify_ssl": true
}
```

### توضیحات:
- `script_id` → همان Deployment ID
- `auth_key` → همان رمز مرحله قبل

---

## 5) اجرا (Run)


```
python main.py
```

---

## خروجی نهایی

اگر همه چیز درست باشد، این پیام را می‌بینید:

```
HTTP proxy is running on 127.0.0.1:8085
```

---

