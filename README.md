<div align="center">

# 🛡️ RVG Gateway

**پنل مدیریت و گیتوی چندپروتکلی، سریع، ماژولار و خودکار**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-Private-red?style=for-the-badge)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

</div>

---

## ✨ درباره‌ی پروژه

**RVG Gateway** یک سرویس گیتوی async و سبک‌وزنه که روی **FastAPI** ساخته شده و چند پروتکل تونل‌سازی رو به‌صورت هم‌زمان، پشت یک نقطه‌ی ورودی واحد (HTTP/WebSocket) سرو می‌کنه. طراحی پروژه کاملاً ماژولاره؛ هر پروتکل توی پکیج مستقل خودش زندگی می‌کنه و پنل مدیریتی، آپدیت خودکار و ارتباط با سرویس مرکزی هم به‌صورت جدا از هسته پیاده‌سازی شدن.

## 🚀 قابلیت‌های کلیدی

| قابلیت | توضیح |
|---|---|
| 🔀 **چندپروتکلی** | پشتیبانی هم‌زمان از `VLESS`، `Trojan`، `Shadowsocks` و `MTProto` روی یک هسته‌ی async |
| 🌐 **انتقال XHTTP/WebSocket** | لایه‌ی انتقال سفارشی برای هر پروتکل جهت عبور روان از پروکسی‌ها و CDN |
| ⚙️ **پنل مدیریتی داخلی** | مدیریت کاربران، وضعیت سرویس و تنظیمات از طریق `main.py` / `pages.py` |
| ☁️ **اتصال به سرویس مرکزی** | ثبت خودکار instance، دریافت اعلان‌ها و پیام‌های پشتیبانی از طریق Cloudflare Worker (`central.py`) |
| 🔄 **آپدیت خودکار** | بررسی نسخه و بروزرسانی پنل از روی مانیفست JSON، به همراه تاریخچه‌ی کامل آپدیت‌ها (`updater.py`) |
| 🤖 **اتوماسیون دامنه/پروکسی روی Railway** | ساخت و مدیریت خودکار TCP proxy و دامنه از طریق GraphQL API (`bottokentcpproxy.py`, `botgeneratedomin.py`) |
| 🔐 **امنیت پیش‌فرض** | ذخیره‌ی امن secret/credentials، هش پسورد، و پیکربندی کامل از طریق متغیرهای محیطی |

## 🏗️ ساختار پروژه

```
RVG/
├── main.py                  # هسته‌ی FastAPI، مسیرها و مدیریت WebSocket
├── pages.py                 # رابط کاربری پنل (HTML/JS تعبیه‌شده)
├── central.py                # ارتباط با سرویس مرکزی (Cloudflare Worker)
├── updater.py                # سیستم بروزرسانی خودکار + تاریخچه
├── botgeneratedomin.py       # تولید انبوه دامنه روی Railway
├── bottokentcpproxy.py       # ساخت خودکار TCP Proxy روی Railway
├── requirements.txt
└── protocol/
    ├── vless/                 # پیاده‌سازی کامل VLESS + XHTTP/WebSocket
    ├── trojan/                # پیاده‌سازی کامل Trojan + XHTTP/WebSocket
    ├── shadowsocks/            # پیاده‌سازی Shadowsocks + XHTTP/WebSocket
    └── mtproto/                # پیاده‌سازی MTProto
```

## 🧰 تکنولوژی‌ها

- **FastAPI** + **Uvicorn** (`uvloop`, `httptools`) برای کارایی بالای async
- **httpx** (با پشتیبانی HTTP/2) برای ارتباطات خارجی
- **websockets** برای انتقال real-time
- **cryptography** برای عملیات رمزنگاری پروتکل‌ها
- **aiofiles** برای I/O غیرمسدودکننده روی دیسک





پیکربندی از طریق متغیرهای محیطی (`DATA_DIR`, `SECRET_KEY`, `CENTRAL_URL`, `UPDATE_MANIFEST_URL` و ...) قابل تنظیم است.

---

<div align="center">

_بخشی از پروژه‌های [arvin341az-glitch](https://github.com/arvin341az-glitch)_

</div>
