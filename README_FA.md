# MHR-CFW — راهنمای کامل راه‌اندازی

<div dir="rtl">

[![GitHub](https://img.shields.io/badge/GitHub-MasterHttpRelayVPN-blue?logo=github)](https://github.com/denuitt1/mhr-cfw)

| [English](README.md) | [Persian](README_FA.md) |
| :---: | :---: |

---

### آموزش ویدیویی
[![Watch the video](https://img.youtube.com/vi/L3lJZrAqqUQ/maxresdefault.jpg)](https://youtu.be/L3lJZrAqqUQ)

- لینک یوتیوب: https://youtu.be/L3lJZrAqqUQ
- لینک داخلی داناود ویدیو: https://nc.thearthur.ir/s/YaCp4zAzepHJKi2

---

## فهرست مطالب

- [پروژه چیست؟](#پروژه-چیست)
- [چطور کار می‌کند؟](#چطور-کار-میکند)
- [پیش‌نیازها](#پیشنیازها)
- [مرحله ۱ — دریافت کد](#مرحله-۱--دریافت-کد)
- [مرحله ۲ — ساخت Cloudflare Worker](#مرحله-۲--ساخت-cloudflare-worker)
- [مرحله ۳ — ساخت Google Apps Script](#مرحله-۳--ساخت-google-apps-script)
- [مرحله ۴ — تنظیم فایل config.json](#مرحله-۴--تنظیم-فایل-configjson)
- [مرحله ۵ — اجرا](#مرحله-۵--اجرا)
- [مرحله ۶ — تنظیم مرورگر](#مرحله-۶--تنظیم-مرورگر)
- [مرحله ۷ — تست اتصال](#مرحله-۷--تست-اتصال)
- [اختیاری — IP خروجی پایدار با Upstream Forwarder](#اختیاری--ip-خروجی-پایدار-با-upstream-forwarder)
- [تنظیمات پیشرفته config.json](#تنظیمات-پیشرفته-configjson)
- [ابزار اسکن IP گوگل](#ابزار-اسکن-ip-گوگل)
- [اشتراک‌گذاری در شبکه محلی (LAN)](#اشتراکگذاری-در-شبکه-محلی-lan)
- [راه‌اندازی روی لینوکس و مک](#راهاندازی-روی-لینوکس-و-مک)
- [عیب‌یابی](#عیبیابی)
- [سؤالات متداول](#سؤالات-متداول)
- [سلب مسئولیت](#سلب-مسئولیت)

---

## پروژه چیست؟

**MHR-CFW** یک پروکسی محلی است که ترافیک اینترنت شما را از طریق زیرساخت Google و Cloudflare عبور می‌دهد تا سیستم‌های DPI (بازرسی عمیق بسته) نتوانند آن را شناسایی و فیلتر کنند.

از دید سیستم فیلترینگ، همه ترافیک شما شبیه ارتباط عادی با `www.google.com` به نظر می‌رسد، در حالی که درخواست‌های واقعی شما به هر سایتی که بخواهید ارسال می‌شوند.

---

## چطور کار می‌کند؟

```
مرورگر شما
    │
    ▼
پروکسی محلی (127.0.0.1:8085)
    │  ← رمزگشایی TLS محلی (MITM)
    ▼
اتصال TLS به Google با SNI=www.google.com
    │  ← از دید فیلترینگ: ترافیک عادی گوگل
    ▼
Google Apps Script (script.google.com)
    │  ← رله JSON داخل زیرساخت گوگل
    ▼
Cloudflare Worker
    │  ← خروج از طریق IP کلودفلر
    ▼
سایت مقصد
```

**مزایای این معماری:**
- سیستم DPI فقط SNI=`www.google.com` می‌بیند
- IP مقصد متعلق به گوگل است (مسدود نمی‌شود)
- محتوای واقعی درخواست داخل TLS رمزگذاری شده و پنهان است
- IP نهایی شما IP کلودفلر است، نه IP واقعی‌تان

---

## پیش‌نیازها

قبل از شروع به موارد زیر نیاز دارید:

| مورد | توضیح |
|------|-------|
| **Python 3.10 یا بالاتر** | روی سیستم نصب باشد |
| **حساب Google** | برای ساخت Apps Script |
| **حساب Cloudflare** | برای ساخت Worker (رایگان) |
| **Git** (اختیاری) | برای دریافت کد |

### بررسی نسخه Python

**ویندوز — PowerShell یا CMD:**
```
python --version
```
یا:
```
py --version
```

**لینوکس / مک — ترمینال:**
```bash
python3 --version
```

اگر خروجی `Python 3.10.x` یا بالاتر بود آماده‌اید. در غیر این صورت از [python.org](https://www.python.org/downloads/) نصب کنید.

> **ویندوز:** هنگام نصب Python، تیک گزینه **"Add Python to PATH"** را حتماً بزنید.

---

## مرحله ۱ — دریافت کد

### روش اول: با Git

```bash
git clone https://github.com/denuitt1/mhr-cfw.git
cd mhr-cfw
```

### روش دوم: دانلود مستقیم

از GitHub روی **Code → Download ZIP** کلیک کنید، فایل را از حالت فشرده خارج کرده و وارد پوشه آن شوید.

### ساخت محیط مجازی Python (توصیه شده)

محیط مجازی یا `virtualenv` باعث می‌شود کتابخانه‌های این پروژه با سایر پروژه‌های Python روی سیستم شما تداخل نداشته باشند.

**ویندوز:**
```
python -m venv .venv
.venv\Scripts\activate
```
پس از فعال شدن، ابتدای خط ترمینال به این شکل تغییر می‌کند:
```
(.venv) C:\Users\...>
```

**لینوکس / مک:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```
پس از فعال شدن:
```
(.venv) user@host:~/mhr-cfw$
```

> برای **خروج** از محیط مجازی در هر زمان، کافی است تایپ کنید:
> ```
> deactivate
> ```

### نصب کتابخانه‌ها

```
pip install -r requirements.txt
```

اگر دسترسی مستقیم به PyPI ندارید:
```
pip install -r requirements.txt -i https://mirror-pypi.runflare.com/simple/ --trusted-host mirror-pypi.runflare.com
```

---

## مرحله ۲ — ساخت Cloudflare Worker

Cloudflare Worker نقش «خروجی» ترافیک را دارد — درخواست را از Apps Script دریافت کرده و به سایت مقصد ارسال می‌کند. IP نهایی‌ای که سایت می‌بیند، IP کلودفلر است.

### گام‌ به گام:

**۱.** به [dash.cloudflare.com](https://dash.cloudflare.com/) بروید و وارد حساب کاربری‌تان شوید.
> اگر حساب ندارید از همین لینک رایگان ثبت‌نام کنید.

**۲.** از منوی سمت چپ، روی **Compute (Workers)** کلیک کنید.

**۳.** روی **Workers & Pages** کلیک کنید.

**۴.** دکمه **Create** را بزنید.

**۵.** گزینه **Start with Hello World** را انتخاب کنید.

**۶.** یک نام دلخواه برای Worker خود بدهید (مثلاً `my-relay`) و دکمه **Deploy** را بزنید.

**۷.** پس از Deploy، روی **Edit code** کلیک کنید.

**۸.** تمام کد پیش‌فرض داخل ویرایشگر را انتخاب و **حذف** کنید.
> در ویندوز: `Ctrl+A` سپس `Delete`
> در مک: `Cmd+A` سپس `Delete`

**۹.** فایل `script/worker.js` را از پوشه پروژه با یک ویرایشگر متن باز کنید (مثلاً Notepad، VS Code، یا Gedit).

**۱۰.** تمام محتوای آن را کپی (`Ctrl+A` سپس `Ctrl+C`) و داخل ویرایشگر Cloudflare **Paste** کنید (`Ctrl+V`).

**۱۱. مهم:** این خط را پیدا کنید:
```javascript
const WORKER_URL = "myworker.workers.dev";
```
آدرس `myworker.workers.dev` را با **آدرس Worker خودتان** جایگزین کنید. آدرس Worker شما در بالای صفحه کلودفلر نمایش داده می‌شود (مثلاً `my-relay.yourname.workers.dev`).

**۱۲.** دکمه **Deploy** را بزنید.

**۱۳.** آدرس Worker خود را یادداشت کنید — در مرحله بعد به آن نیاز دارید.
آدرس معمولاً به شکل `https://my-relay.yourname.workers.dev` است.

---

## مرحله ۳ — ساخت Google Apps Script

Apps Script نقش «دروازه» را دارد — درخواست‌های پروکسی محلی شما را دریافت کرده و از طریق زیرساخت گوگل به Worker کلودفلر ارسال می‌کند.

### گام به گام:

**۱.** به [script.google.com](https://script.google.com/) بروید و با همان حساب Google وارد شوید.

**۲.** روی **New project** (پروژه جدید) کلیک کنید.

**۳.** در ویرایشگر باز‌شده، تمام کد پیش‌فرض (`function myFunction() {}`) را **حذف** کنید.

**۴.** فایل `script/Code.gs` را از پوشه پروژه با یک ویرایشگر متن باز کرده، کل محتوا را کپی و داخل ویرایشگر Apps Script **Paste** کنید.

**۵. مهم:** این دو خط را پیدا کنید:
```javascript
const AUTH_KEY = "STRONG_SECRET_KEY";
const WORKER_URL = "https://example.workers.dev";
```

- **AUTH_KEY** را با یک رمز دلخواه قوی (حداقل ۲۰ کاراکتر، ترکیب حروف و اعداد) تغییر دهید.
  مثال: `const AUTH_KEY = "mYs3cr3tP@ss2024xZ9k";`
  > این رمز را یادداشت کنید — در `config.json` هم باید همین رمز را وارد کنید.

- **WORKER_URL** را با آدرس Worker کلودفلر که در مرحله قبل ساختید تغییر دهید.
  مثال: `const WORKER_URL = "https://my-relay.yourname.workers.dev";`

**۶.** کد را ذخیره کنید (`Ctrl+S` یا `Cmd+S`).

**۷.** از منوی بالا روی **Deploy** کلیک کنید، سپس **New deployment** را انتخاب کنید.

**۸.** در پنجره باز‌شده:
- روی آیکون چرخ‌دنده (⚙️) کنار «Select type» کلیک کنید
- **Web app** را انتخاب کنید

**۹.** تنظیمات را به این شکل پر کنید:
```
Description     : هر چیزی دلتان بخواهد (مثلاً "relay v1")
Execute as      : Me
Who has access  : Anyone
```

**۱۰.** روی **Deploy** کلیک کنید.

**۱۱.** اگر اولین بار است، Google از شما می‌خواهد دسترسی‌ها را تأیید کنید:
- روی **Authorize access** کلیک کنید
- حساب Google خود را انتخاب کنید
- اگر پیام «Google hasn't verified this app» نمایش داده شد:
  - روی **Advanced** کلیک کنید
  - روی **Go to [نام پروژه] (unsafe)** کلیک کنید
  - روی **Allow** کلیک کنید

**۱۲.** پس از Deploy موفق، یک **Deployment ID** به شما نمایش داده می‌شود که شکلی مانند این دارد:
```
AKfycbz...................................xYZ
```
این ID را کپی کرده و نگه دارید — در مرحله بعد نیاز است.

---

## مرحله ۴ — تنظیم فایل config.json

در پوشه پروژه، فایلی به نام `config.example.json` وجود دارد. باید از روی آن یک فایل `config.json` بسازید.

**ویندوز:**
```
copy config.example.json config.json
```

**لینوکس / مک:**
```bash
cp config.example.json config.json
```

حالا `config.json` را با یک ویرایشگر متن باز کنید و مقادیر لازم را تغییر دهید:

**ویندوز (Notepad):**
```
notepad config.json
```

**لینوکس (nano):**
```bash
nano config.json
```
> برای **ذخیره** در nano: `Ctrl+O` سپس `Enter`
> برای **خروج** از nano: `Ctrl+X`

**لینوکس (vim):**
```bash
vim config.json
```
> برای **رفتن به حالت ویرایش** در vim: کلید `i` را بزنید
> برای **ذخیره و خروج** از vim: کلید `Esc` سپس تایپ کنید `:wq` و `Enter`

### حداقل تنظیمات لازم:

```json
{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "DEPLOYMENT_ID_را_اینجا_بگذارید",
  "auth_key": "همان_رمزی_که_در_Code.gs_گذاشتید",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "socks5_enabled": true,
  "socks5_port": 1080,
  "log_level": "INFO",
  "verify_ssl": true
}
```

- **script_id**: Deployment ID که در مرحله ۳ کپی کردید
- **auth_key**: رمزی که در `Code.gs` برای `AUTH_KEY` گذاشتید (باید دقیقاً یکسان باشد)

---

## مرحله ۵ — اجرا

### روش ساده (توصیه شده)

**ویندوز:**
فایل `run.bat` را دوبار کلیک کنید یا در CMD:
```
run.bat
```

**لینوکس / مک:**
```bash
chmod +x run.sh
./run.sh
```

این اسکریپت‌ها به صورت خودکار:
- محیط مجازی Python می‌سازند
- وابستگی‌ها را نصب می‌کنند
- اگر `config.json` نداشته باشید، wizard راه‌اندازی را اجرا می‌کنند
- پروکسی را روشن می‌کنند

### روش دستی

اگر محیط مجازی را خودتان ساخته‌اید:

```bash
# ابتدا محیط مجازی را فعال کنید (اگر نکرده‌اید)
# ویندوز:
.venv\Scripts\activate
# لینوکس/مک:
source .venv/bin/activate

# سپس اجرا کنید:
python main.py
```

### خروجی موفق

اگر همه چیز درست باشد، پیام‌هایی شبیه به این می‌بینید:

```
╭──────────────────────────────────────────────────────────────────────╮
│ mhr-cfw          Domain-Fronted GAS-CFW Relay                v1.1.0 │
╰──────────────────────────────────────────────────────────────────────╯
10:25:43  •  INFO   [Main    ]  DomainFront Tunnel starting (Apps Script relay)
10:25:43  •  INFO   [Main    ]  Apps Script relay : SNI=www.google.com → script.google.com
10:25:43  •  INFO   [Main    ]  Script ID : AKfycbz...
10:25:44  •  INFO   [Main    ]  MITM CA is already trusted.
10:25:44  •  INFO   [Proxy   ]  HTTP proxy listening on 127.0.0.1:8085
10:25:44  •  INFO   [Proxy   ]  SOCKS5 proxy listening on 127.0.0.1:1080
10:25:44  •  INFO   [Fronter ]  Pre-warmed 28/30 TLS connections
10:25:44  •  INFO   [H2      ]  H2 multiplexing active — one conn handles all requests
```

### نصب گواهی CA (اولین بار)

برای رمزگشایی ترافیک HTTPS، پروژه یک گواهی CA محلی می‌سازد که باید به مرورگر شما اضافه شود.

پروژه سعی می‌کند این کار را **به صورت خودکار** انجام دهد. اگر خودکار کار نکرد:

```bash
python main.py --install-cert
```

در ویندوز ممکن است پنجره‌ای برای تأیید باز شود — روی **Yes** کلیک کنید.

> **نکته:** گواهی CA فقط برای اتصالات از طریق همین پروکسی استفاده می‌شود. هیچ ترافیک خارج از پروکسی تحت تأثیر نیست.

---

## مرحله ۶ — تنظیم مرورگر

پروکسی روی پورت `8085` اجرا می‌شود. باید مرورگر خود را تنظیم کنید تا ترافیک را از طریق این پروکسی بفرستد.

### روش ۱: FoxyProxy (توصیه شده برای Chrome/Firefox)

**۱.** افزونه FoxyProxy را نصب کنید:
- [Chrome](https://chromewebstore.google.com/detail/foxyproxy/gcknhkkoolaabfmlnjonogaaifnjlfnp)
- [Firefox](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/)

**۲.** روی آیکون FoxyProxy کلیک کنید → **Options**

**۳.** روی **Add** کلیک کنید و این اطلاعات را وارد کنید:
```
Proxy Type  : HTTP
Proxy IP    : 127.0.0.1
Port        : 8085
```

**۴.** یک نام دلخواه بدهید (مثلاً «MHR-CFW») و ذخیره کنید.

**۵.** از آیکون FoxyProxy، پروکسی ساخته‌شده را فعال کنید.

### روش ۲: تنظیمات سیستم ویندوز

اگر می‌خواهید همه برنامه‌ها از پروکسی استفاده کنند:

۱. **Settings** → **Network & Internet** → **Proxy**
۲. زیر **Manual proxy setup** گزینه **Use a proxy server** را روشن کنید
۳. آدرس `127.0.0.1` و پورت `8085` را وارد کنید
۴. **Save**

### روش ۳: SOCKS5 (برای برنامه‌های سازگار)

پروجه همچنین یک پروکسی SOCKS5 روی پورت `1080` دارد:
```
Protocol : SOCKS5
Host     : 127.0.0.1
Port     : 1080
```

---

## مرحله ۷ — تست اتصال

پس از اینکه پروکسی روشن و مرورگر تنظیم شد:

**۱.** مرورگر را باز کنید و به آدرس [ipleak.net](https://ipleak.net) بروید.

**۲.** نتیجه موفق:
- IP نمایش‌داده‌شده باید از **Cloudflare** (AS13335) باشد
- IP واقعی شما نباید نمایش داده شود

**۳.** تست دسترسی به سایت فیلترشده: هر سایتی که قبلاً در دسترس نبود را امتحان کنید.

---

## اختیاری — IP خروجی پایدار با Upstream Forwarder

سایت‌هایی که از CAPTCHA استفاده می‌کنند (Cloudflare Turnstile، reCAPTCHA، hCaptcha) توکن حل‌شده را به IP بازکننده‌ی چالش گره می‌زنند. Cloudflare Worker در هر درخواست از IP متفاوتی خروج می‌گیرد، بنابراین حتی پس از حل CAPTCHA، تأیید سمت سرور رد می‌شود. این افزونه‌ی اختیاری به Worker اجازه می‌دهد همه‌ی `fetch()` ها را از طریق یک سرور Node کوچک روی VPS شما (با IP ثابت) عبور دهد — به‌طوری که سایت مقصد همیشه یک IP خروجی ثابت ببیند.

### چه زمانی به این نیاز دارید

- سایت‌های پشت Cloudflare bot challenge شما را به‌صورت حلقه‌ای به صفحه‌ی چالش برمی‌گردانند.
- فرم لاگین بعد از حل reCAPTCHA/hCaptcha رد می‌شود.
- نیاز به پایداری کوکی بین درخواست‌ها دارید (مثل `cf_clearance`).

اگر این مشکلات را ندارید، آن را تنظیم نکنید — Worker دقیقاً مثل قبل کار می‌کند.

### چرا به سرور جداگانه نیاز است

Cloudflare Worker آی‌پی خروجی ثابتی ندارد — هر `fetch()` از یک IP در شبکه‌ی edge کلودفلر خارج می‌شود که دائماً تغییر می‌کند، و دقیقاً همین چیزی است که توکن‌های CAPTCHA وابسته به IP را می‌شکند. گزینه‌های static egress خود کلودفلر (BYOIP، Egress Workers) فقط در پلن Enterprise در دسترس‌اند، بنابراین یک VPS کوچک با IP ثابت ساده‌ترین راه‌حل عملی است. forwarder فقط یک پراکسی نازک است که `fetch()` را از یک آدرس ثابت بازارسال می‌کند.

### ۱. اجرای forwarder روی VPS

پیاده‌سازی مرجع در فایل [`script/upstream_forwarder.js`](script/upstream_forwarder.js) قرار دارد. به Node نسخه ۱۸+ نیاز دارد و هیچ وابستگی خارجی ندارد. آن را پشت Caddy یا nginx با TLS اجرا کنید — Worker آدرس‌های غیر HTTPS را نمی‌پذیرد.

```bash
# روی VPS (مثال Ubuntu/Debian):
sudo apt install -y nodejs   # باید نسخه ۱۸ یا بالاتر باشد
export AUTH_KEY="یک-کلید-تصادفی-حداقل-۳۲-کاراکتر"
export PORT=8787
node script/upstream_forwarder.js
```

تنظیم Caddy برای TLS خودکار:

```
forwarder.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

تست سریع:

```bash
curl -X POST https://forwarder.example.com/fwd \
  -H "x-upstream-auth: $AUTH_KEY" \
  -H "content-type: application/json" \
  -d '{"u":"https://httpbin.org/ip","m":"GET","h":{}}'
```

پاسخ دیکد‌شده باید **IP خود VPS** را نشان دهد.

### ۲. اتصال Worker به forwarder

در Cloudflare dashboard → Worker شما → **Settings → Variables and Secrets**:

| نام | نوع | مقدار |
|-----|-----|-------|
| `UPSTREAM_FORWARDER_URL` | Secret | `https://forwarder.example.com/fwd` |
| `UPSTREAM_AUTH_KEY` | Secret | همان `AUTH_KEY` که روی VPS گذاشتید |
| `UPSTREAM_FAIL_MODE` | Variable | پیش‌فرض `closed` — در صورت خطای forwarder کد ۵۰۲ بازمی‌گرداند. مقدار `open` باعث می‌شود به fetch مستقیم برگردد. |
| `UPSTREAM_TIMEOUT_MS` | Variable (اختیاری) | پیش‌فرض `25000` |

ذخیره و Worker را دوباره Deploy کنید.

### ۳. تست

از طریق پروکسی به `https://httpbin.org/ip` بروید — باید **IP VPS** را ببینید، نه Cloudflare. سپس سایتی که قبلاً CAPTCHA آن کار نمی‌کرد را امتحان کنید — چالش باید این بار به‌درستی تأیید شود.

> forwarder بدون `AUTH_KEY` راه‌اندازی نمی‌شود. هر کسی که آدرس و کلید را داشته باشد می‌تواند از آن به‌عنوان رله استفاده کند، بنابراین هر دو را محرمانه نگه دارید.

---

## تنظیمات پیشرفته config.json

فایل `config.json` گزینه‌های زیادی دارد که می‌توانید برحسب نیاز تنظیم کنید:

### تنظیمات اصلی

| کلید | پیش‌فرض | توضیح |
|------|---------|-------|
| `google_ip` | `216.239.38.120` | IP سرور Google برای domain fronting. از ابزار اسکن برای یافتن سریع‌ترین IP استفاده کنید. |
| `front_domain` | `www.google.com` | دامنه‌ای که در SNI به سیستم فیلترینگ نمایش داده می‌شود |
| `script_id` | — | Deployment ID گوگل Apps Script شما |
| `auth_key` | — | رمز مشترک بین پروکسی و Apps Script |
| `listen_host` | `127.0.0.1` | آدرس گوش‌دادن HTTP پروکسی |
| `listen_port` | `8085` | پورت HTTP پروکسی |
| `socks5_enabled` | `true` | فعال‌سازی پروکسی SOCKS5 |
| `socks5_port` | `1080` | پورت SOCKS5 |
| `log_level` | `INFO` | سطح لاگ: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `verify_ssl` | `true` | تأیید گواهی SSL هنگام اتصال به گوگل |

### تنظیمات شبکه و اتصال

| کلید | پیش‌فرض | توضیح |
|------|---------|-------|
| `lan_sharing` | `false` | اشتراک پروکسی با سایر دستگاه‌های شبکه محلی |
| `relay_timeout` | `25` | مهلت زمانی (ثانیه) برای هر درخواست رله |
| `tls_connect_timeout` | `15` | مهلت اتصال TLS به گوگل (ثانیه) |
| `tcp_connect_timeout` | `10` | مهلت اتصال TCP مستقیم (ثانیه) |
| `max_response_body_bytes` | `209715200` | حداکثر حجم پاسخ (200 مگابایت) |
| `parallel_relay` | `1` | تعداد Apps Script که به صورت موازی استفاده می‌شوند (نیاز به چند `script_id`) |

### چند script_id برای سرعت بیشتر

اگر چندین پروژه Apps Script دارید، می‌توانید ID آن‌ها را به صورت لیست بدهید:

```json
{
  "script_ids": [
    "AKfycbzFIRSTID...",
    "AKfycbzSECONDID...",
    "AKfycbzTHIRDID..."
  ],
  "parallel_relay": 3
}
```

با `parallel_relay: 3`، پروکسی هر درخواست را به **هر سه** script به صورت همزمان می‌فرستد و سریع‌ترین پاسخ را برمی‌گرداند — این latency را به شدت کاهش می‌دهد.

### تنظیمات دانلود موازی (Parallel Download)

برای فایل‌های بزرگ، پروکسی از قابلیت HTTP Range استفاده می‌کند تا چندین قطعه را به صورت موازی دانلود کند:

```json
{
  "chunked_download_extensions": [".mp4", ".mkv", ".zip", ".iso"],
  "chunked_download_min_size": 5242880,
  "chunked_download_chunk_size": 524288,
  "chunked_download_max_parallel": 8,
  "chunked_download_max_chunks": 256
}
```

| کلید | توضیح |
|------|-------|
| `chunked_download_extensions` | پسوندهایی که دانلود موازی روی آن‌ها فعال می‌شود |
| `chunked_download_min_size` | حداقل حجم فایل برای فعال‌شدن دانلود موازی (بایت) — پیش‌فرض 5MB |
| `chunked_download_chunk_size` | حجم هر قطعه (بایت) — پیش‌فرض 512KB |
| `chunked_download_max_parallel` | حداکثر تعداد قطعه‌های هم‌زمان |
| `chunked_download_max_chunks` | حداکثر تعداد کل قطعه‌ها |

### قوانین مسیریابی

```json
{
  "block_hosts": ["ads.example.com", ".adserver.net"],
  "bypass_hosts": ["localhost", ".local", ".lan"],
  "youtube_via_relay": false,
  "hosts": {
    "custom.example.com": "1.2.3.4"
  }
}
```

| کلید | توضیح |
|------|-------|
| `block_hosts` | دامنه‌هایی که کاملاً مسدود می‌شوند. قوانین با `.` مثل `.adserver.net` شامل همه زیردامنه‌ها می‌شوند |
| `bypass_hosts` | دامنه‌هایی که مستقیم (بدون رله) اتصال برقرار می‌شوند |
| `youtube_via_relay` | اگر `true` باشد، YouTube از طریق Apps Script رله می‌شود (پیش‌فرض: مستقیم با SNI rewrite) |
| `hosts` | نگاشت دستی دامنه به IP (مثل hosts سیستم‌عامل) |

### تنظیمات گوگل

```json
{
  "direct_google_exclude": ["gemini.google.com", "mail.google.com"],
  "direct_google_allow": ["www.google.com", "safebrowsing.google.com"]
}
```

سرویس‌های گوگل که در `direct_google_exclude` هستند از طریق Apps Script رله می‌شوند (نه مستقیم). سرویس‌های `direct_google_allow` مستقیم به IP گوگل متصل می‌شوند.

---

## ابزار اسکن IP گوگل

اگر پروکسی کند است یا IP گوگل فعلی مسدود شده، می‌توانید سریع‌ترین IP موجود را پیدا کنید:

```bash
python main.py --scan
```

خروجی نمونه:
```
Scanning 26 Google frontend IPs
  SNI: www.google.com
  Timeout: 4s per IP
  Concurrency: 8 parallel probes

IP                   LATENCY      STATUS
-------------------- ------------ -------------------------
216.239.38.120            42ms   OK
142.250.80.142            45ms   OK
172.217.14.206            78ms   OK
...

Top 3 fastest IPs:
  1. 216.239.38.120 (42ms)
  2. 142.250.80.142 (45ms)
  3. 172.217.14.206 (78ms)

Recommended: Set "google_ip": "216.239.38.120" in config.json
```

IP پیشنهادشده را در `config.json` در قسمت `google_ip` قرار دهید.

---

## اشتراک‌گذاری در شبکه محلی (LAN)

اگر می‌خواهید موبایل یا سایر دستگاه‌های خانگی هم از این پروکسی استفاده کنند:

در `config.json`:
```json
{
  "lan_sharing": true
}
```

پروکسی به صورت خودکار روی همه رابط‌های شبکه (`0.0.0.0`) گوش می‌دهد و آدرس‌های قابل دسترس از شبکه محلی را لاگ می‌کند:

```
INFO  [Main]  LAN HTTP proxy   : 192.168.1.100:8085, 192.168.1.100:8085
INFO  [Main]  LAN SOCKS5 proxy : 192.168.1.100:1080
```

**تنظیم موبایل (Android/iOS):**
1. به تنظیمات WiFi بروید
2. شبکه متصل را نگه دارید یا روی آیکون ⚙️ بزنید
3. گزینه **Proxy** را روی **Manual** بگذارید
4. **Hostname**: آدرس IP لپ‌تاپ/PC شما (مثلاً `192.168.1.100`)
5. **Port**: `8085`

> **توجه:** فایروال ویندوز ممکن است اتصال از شبکه محلی را مسدود کند. اگر موبایل نتوانست متصل شود، یک قانون استثنا در Windows Defender Firewall برای پورت ۸۰۸۵ اضافه کنید.

---

## راه‌اندازی روی لینوکس و مک

تمام مراحل بالا روی لینوکس و مک یکسان است با این تفاوت‌ها:

### نصب Python (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y
```

### نصب Python (Fedora/RHEL)
```bash
sudo dnf install python3 python3-pip git -y
```

### نصب Python (macOS)
```bash
brew install python3 git
```
> اگر Homebrew ندارید: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`

### نصب گواهی CA روی لینوکس

اگر نصب خودکار با خطا روبرو شد:
```bash
sudo python main.py --install-cert
```

برای Ubuntu/Debian می‌توانید دستی هم نصب کنید:
```bash
sudo cp ca/ca.crt /usr/local/share/ca-certificates/mhr-cfw.crt
sudo update-ca-certificates
```

### حذف گواهی CA
```bash
sudo python main.py --uninstall-cert
```

---

## آرگومان‌های خط فرمان

```
python main.py [گزینه‌ها]

  -c, --config PATH       مسیر فایل config (پیش‌فرض: config.json)
  -p, --port PORT         اوررید پورت HTTP
  --host HOST             اوررید آدرس گوش‌دادن
  --socks5-port PORT      اوررید پورت SOCKS5
  --disable-socks5        غیرفعال کردن SOCKS5
  --log-level LEVEL       سطح لاگ (DEBUG/INFO/WARNING/ERROR)
  --install-cert          نصب گواهی CA و خروج
  --uninstall-cert        حذف گواهی CA و خروج
  --no-cert-check         رد شدن از بررسی گواهی CA
  --scan                  اسکن IP های گوگل و خروج
  -v, --version           نمایش نسخه
```

مثال — اجرا با پورت متفاوت بدون تغییر config:
```bash
python main.py -p 9090 --socks5-port 9091 --log-level DEBUG
```

---

## متغیرهای محیطی

می‌توانید به جای تغییر `config.json` از متغیرهای محیطی استفاده کنید:

| متغیر | معادل config |
|-------|-------------|
| `DFT_AUTH_KEY` | `auth_key` |
| `DFT_SCRIPT_ID` | `script_id` |
| `DFT_PORT` | `listen_port` |
| `DFT_HOST` | `listen_host` |
| `DFT_SOCKS5_PORT` | `socks5_port` |
| `DFT_LOG_LEVEL` | `log_level` |
| `DFT_CONFIG` | مسیر فایل config |

**لینوکس/مک:**
```bash
export DFT_AUTH_KEY="my_secret_key"
export DFT_SCRIPT_ID="AKfycbz..."
python main.py
```

**ویندوز CMD:**
```
set DFT_AUTH_KEY=my_secret_key
python main.py
```

---

## عیب‌یابی

### خطا: `auth_key is unset or uses a known placeholder`

**علت:** مقدار `auth_key` در `config.json` تغییر نکرده یا خالی است.

**راه‌حل:** در `config.json` مقدار `auth_key` را به یک رمز واقعی تغییر دهید. این رمز باید **دقیقاً** با مقدار `AUTH_KEY` در فایل `Code.gs` یکسان باشد.

---

### خطا: `Missing 'script_id' in config`

**علت:** Deployment ID وارد نشده یا مقدار پیش‌فرض تغییر نکرده.

**راه‌حل:** Deployment ID را از Google Apps Script کپی و در `config.json` وارد کنید.

---

### پروکسی اجرا می‌شود اما سایت‌ها باز نمی‌شوند

**۱. بررسی کنید مرورگر به پروکسی متصل است:**
- در FoxyProxy مطمئن شوید پروکسی فعال است
- در ipleak.net بررسی کنید IP تغییر کرده باشد

**۲. AUTH_KEY را بررسی کنید:**
- مقدار `auth_key` در `config.json` باید **کاملاً یکسان** با `AUTH_KEY` در `Code.gs` باشد
- به فاصله، کوچک/بزرگ‌بودن حروف، و کاراکترهای اضافه دقت کنید

**۳. پس از تغییر Code.gs باید Deploy جدید بسازید:**
- هر بار که `Code.gs` را تغییر می‌دهید، باید دوباره **Deploy → New deployment** کنید
- از Deployment ID **جدید** استفاده کنید

**۴. google_ip را بررسی کنید:**
- دستور `python main.py --scan` را اجرا کنید
- سریع‌ترین IP را در `config.json` قرار دهید

---

### خطا در لاگ: `unauthorized`

**علت:** `AUTH_KEY` در Apps Script با `auth_key` در `config.json` مطابقت ندارد.

**راه‌حل:**
1. `Code.gs` را در Apps Script باز کنید
2. مقدار `AUTH_KEY` را یادداشت کنید
3. همان مقدار را در `config.json` برای `auth_key` قرار دهید
4. سرویس را ری‌استارت کنید

---

### خطا: `MITM CA is not trusted`

**علت:** گواهی CA نصب نشده یا نصب آن ناموفق بوده.

**راه‌حل:**
```bash
# اجرا با دسترسی ادمین:
# ویندوز: CMD را به عنوان Administrator باز کنید
python main.py --install-cert

# لینوکس/مک:
sudo python main.py --install-cert
```

اگر مشکل ادامه داشت، گواهی را **دستی** نصب کنید:
1. فایل `ca/ca.crt` را پیدا کنید
2. روی آن دوبار کلیک کنید (ویندوز)
3. **Install Certificate** → **Local Machine** → **Trusted Root Certification Authorities**

---

### پروکسی در ویندوز کند است یا قطع می‌شود

برخی مواقع Windows Defender یا آنتی‌ویروس ترافیک پروکسی را بررسی می‌کند.

پوشه پروژه را به استثناهای آنتی‌ویروس اضافه کنید:
- Windows Security → Virus & threat protection → Manage settings → Exclusions

---

### پیام: `H2 multiplexing` نمی‌آید

این پیام نشان می‌دهد کتابخانه `h2` نصب نشده. بدون آن پروکسی با HTTP/1.1 کار می‌کند (کمی کندتر).

برای نصب:
```bash
pip install h2>=4.1.0
```

---

## سؤالات متداول

**آیا این پروژه رایگان است؟**
بله، کاملاً رایگان است. Google Apps Script و Cloudflare Workers هر دو پلن رایگان دارند که برای استفاده شخصی کافی است.

**محدودیت‌های Apps Script چیست؟**
در پلن رایگان، Google Apps Script روزانه محدودیت ۶ دقیقه زمان اجرا و ۲۰,۰۰۰ درخواست URL دارد. برای استفاده معمول روزانه معمولاً کافی است. اگر پیام `quota_exceeded` در لاگ دیدید، روز بعد سهمیه تجدید می‌شود.

**آیا می‌توانم چند نفر از یک Apps Script استفاده کنیم؟**
بله، اما سهمیه روزانه مشترک می‌شود. بهتر است هر نفر پروژه مجزای خود را بسازد.

**آیا ترافیک شما توسط گوگل دیده می‌شود؟**
Apps Script درخواست‌ها را از طریق `UrlFetchApp` ارسال می‌کند. محتوای JSON رمزگذاری‌نشده توسط Apps Script پردازش می‌شود. برای اطلاعات حساس از HTTPS اطمینان حاصل کنید (که به صورت پیش‌فرض رمزگذاری شده باقی می‌ماند).

**آیا IPv6 پشتیبانی می‌شود?**
پروکسی HTTP روی IPv4 گوش می‌دهد. اتصالات مستقیم (مثل bypass) هم IPv4 و هم IPv6 را پشتیبانی می‌کنند.

**گواهی CA را چطور حذف کنم؟**
```bash
python main.py --uninstall-cert
```
یا فایل `run.bat --uninstall-cert` را اجرا کنید.

**آیا پروکسی بعد از ری‌استارت سیستم خودکار اجرا می‌شود؟**
خیر، باید دستی اجرا شود. برای راه‌اندازی خودکار در ویندوز می‌توانید یک Task در Task Scheduler بسازید. در لینوکس می‌توانید یک systemd service بنویسید.

---

## ساختار فایل‌های پروژه

```
mhr-cfw/
├── main.py                  ← نقطه ورود اصلی
├── setup.py                 ← wizard راه‌اندازی
├── config.json              ← تنظیمات شما (ساخته نمی‌شود، باید بسازید)
├── config.example.json      ← نمونه تنظیمات با همه گزینه‌ها
├── requirements.txt         ← وابستگی‌های Python
├── run.bat                  ← اجراکننده ویندوز
├── run.sh                   ← اجراکننده لینوکس/مک
├── ca/                      ← گواهی CA (خودکار ساخته می‌شود)
│   ├── ca.crt               ← گواهی عمومی CA
│   └── ca.key               ← کلید خصوصی CA (محرمانه)
├── script/
│   ├── Code.gs              ← کد Google Apps Script
│   └── worker.js            ← کد Cloudflare Worker
└── src/
    ├── proxy_server.py      ← سرور HTTP/SOCKS5 محلی
    ├── domain_fronter.py    ← موتور رله Apps Script
    ├── h2_transport.py      ← انتقال HTTP/2
    ├── mitm.py              ← مدیریت گواهی MITM
    ├── cert_installer.py    ← نصب CA در سیستم‌عامل
    ├── codec.py             ← رمزگشایی gzip/brotli/zstd
    ├── constants.py         ← ثابت‌های قابل تنظیم
    ├── google_ip_scanner.py ← اسکنر IP گوگل
    ├── lan_utils.py         ← ابزارهای شبکه محلی
    └── logging_utils.py     ← لاگ‌گذاری رنگی
```

> **هرگز** فایل `ca/ca.key` را به کسی ندهید یا در اینترنت آپلود نکنید.

---

## سلب مسئولیت

این نرم‌افزار فقط برای اهداف آموزشی، تحقیقاتی و تست ارائه شده است.

- نرم‌افزار «همانطور که هست» (AS IS) ارائه می‌شود بدون هیچ ضمانتی
- توسعه‌دهندگان مسئولیتی در قبال خسارات احتمالی ندارند
- رعایت قوانین محلی، ملی و بین‌المللی بر عهده کاربر است
- رعایت شرایط استفاده از سرویس‌های Google و Cloudflare بر عهده کاربر است

</div>
