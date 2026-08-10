> [!CAUTION]
> **Security Notice**
> If you believe this project does not comply with GitHub's Community Guidelines or Acceptable Use Policies, please let us know. We make every effort to ensure all our projects are secure and compliant with GitHub's policies.

# 🚀 RVG Gateway – codebox

دروازه (Gateway) سریع و مدرن برای تونل‌زنی VLESS روی WebSocket + HTTP Proxy، با داشبورد مدیریتی زیبا و قابلیت ساخت لینک‌های اختصاصی با محدودیت ترافیک.

لینک ویدیو اموزش
https://youtu.be/nTq2vDmC0Ks

کانال تلگرام

https://t.me/CodeBoxo

---

## ✨ ویژگی‌ها

- 🔌 تونل VLESS over WebSocket (TLS 443)
- 🌐 HTTP Proxy داخلی
- 📊 داشبورد مدیریتی کامل (آمار، نمودار ترافیک، اتصالات زنده)
- 🔗 مدیریت لینک‌های نامحدود با محدودیت ترافیک اختصاصی (MB/GB)
- ✅ فعال/غیرفعال‌سازی هر لینک به‌صورت لحظه‌ای
- 📱 خروجی QR Code برای هر لینک
- 🛡️ Fingerprint Spoofing (Chrome)

---

## 1️⃣ Fork روی گیت‌هاب

ابتدا روی دکمه **Fork** کلیک کنید تا این ریپازیتوری را به حساب خود منتقل کنید:

```bash
https://github.com/arvin341az-glitch/RVG/
```

---

## 2️⃣ Deploy روی Railway

1. وارد سایت [Railway.app](https://railway.app) شوید.
2. روی **New Project → Deploy from GitHub repo** کلیک کنید.
3. ریپازیتوری Fork شده را انتخاب کنید.
4. Railway به‌صورت خودکار پروژه را **Deploy** می‌کند.

> 💡 پس از دیپلوی، یک دامنه عمومی (Public Domain) برای سرویس خود از تنظیمات Railway فعال کنید تا متغیر `RAILWAY_PUBLIC_DOMAIN` به‌درستی مقداردهی شود.

---

## 3️⃣ اتصال به کانفیگ‌ها

پس از دیپلوی موفق:

1. به آدرس `https://your-app.up.railway.app/dashboard` بروید.
2. در صفحه **داشبورد کلی**، لینک VLESS پیش‌فرض (بدون محدودیت) را مشاهده و کپی کنید.
3. این لینک را در کلاینت دلخواه (v2rayNG، NekoBox، Streisand و...) وارد کنید.
4. برای ساخت لینک‌های جداگانه با محدودیت ترافیک، به بخش **مدیریت لینک‌ها** بروید.

---

## ⚠️ نکته مهم

تمام لینک‌ها و آمار مصرف به‌صورت **درون‌حافظه (in-memory)** ذخیره می‌شوند و با هر بار ری‌استارت سرویس روی Railway، ریست خواهند شد. برای ذخیره‌سازی دائمی، اتصال به یک دیتابیس (Redis یا PostgreSQL) پیشنهاد می‌شود.

---

<p align="center">ساخته‌شده با ❤️ توسط <b>codebox</b></p>

---

## 💰 حمایت مالی (Donate)

اگر این پروژه به شما کمک کرد و خواستید از توسعه‌دهنده حمایت کنید:

https://wallets.arvin341az.workers.dev

🙏 از حمایت شما متشکریم!
