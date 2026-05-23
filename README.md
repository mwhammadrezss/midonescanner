<div align="center">

<img src="assets/icons/app_icon.png" width="140" />

# MidONe Scanner
### اسکنر حرفه‌ای آی‌پی تمیز — شیر خورشید CDN Scanner

[![Release](https://img.shields.io/github/v/release/mwhammadrezss/midonescanner?label=آخرین%20نسخه&style=flat-square&color=brightgreen)](https://github.com/mwhammadrezss/midonescanner/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/mwhammadrezss/midonescanner/total?label=دانلود&style=flat-square&color=blue)](https://github.com/mwhammadrezss/midonescanner/releases/latest)
[![Platform](https://img.shields.io/badge/Platform-Android-green?style=flat-square&logo=android)](https://github.com/mwhammadrezss/midonescanner/releases/latest)
[![Telegram](https://img.shields.io/badge/Telegram-@mmdrlx-blue?style=flat-square&logo=telegram)](https://t.me/mmdrlx)

<br/>

[**⬇️ دانلود APK**](https://github.com/mwhammadrezss/midonescanner/releases/download/v6.2-flutter-build90/app-release.apk) &nbsp;·&nbsp; [**📣 کانال تلگرام**](https://t.me/mmdrlx)

</div>

---

## 🔍 چرا MidONe Scanner؟

بیشتر ابزارهای اسکن IP فقط یک **ping** ساده می‌زنند — عددی که هیچ ربطی به سرعت واقعی اتصال ندارد. MidONe Scanner متفاوت است:

> **داده واقعی دانلود می‌کند.** سرعتی که اپ نشان می‌دهد، همان چیزی است که در واقعیت تجربه خواهید کرد.

---

## ⚙️ معماری و عملکرد

### 🧵 پردازش موازی (Multi-thread)
برنامه با معماری چندرشته‌ای اجرا می‌شود و همزمان ده‌ها آی‌پی را اسکن می‌کند — بدون کوچک‌ترین افت فریم یا هنگ در رابط کاربری.

### 🌐 تشخیص هوشمند CDN
سیستم CDN Detection با ارسال SNIهای معتبر و مرتبط با هر سرور، سیستم‌های فیلترینگ را دور می‌زند و ارتباطی امن و باز شبیه‌سازی می‌کند.

**CDNهای پشتیبانی‌شده:**
`Cloudflare` · `Akamai` · `Google` · `Amazon CloudFront` · `Azure` · `Fastly` · `Iranian CDNs`

### 🔁 تست پایداری × ۵ (Reliability)
برای حذف آی‌پی‌های ناپایدار، هر آی‌پی **پنج بار متوالی** زیر فشار شبکه تست می‌شود. هر بار که Packet Loss یا Timeout ثبت شود، آن آی‌پی فوری از چرخه حذف می‌گردد.

### 📡 تست سرعت واقعی
به جای ping، داده‌ی واقعی دانلود می‌شود. اگر ISP سرعت را پس از چند ثانیه محدود کند **(Throttle)**، بلافاصله شناسایی و از نتایج جدا می‌شود.

### 📊 الگوریتم امتیازدهی
یک فرمول ریاضی دقیق، چهار فاکتور را با هم ترکیب می‌کند:

```
Score = (Speed × 0.55) + (Latency × 0.20) + (Jitter × 0.10) + (Reliability × 0.15)
```

خروجی: یک لیست رتبه‌بندی‌شده، بدون آی‌پی فیک، آماده استفاده.

---

## ✨ امکانات

| امکان | توضیح |
|-------|--------|
| 🔍 **Simple Mode** | اسکن سریع با SNI ثابت — ایده‌آل برای تست اولیه |
| 🧠 **Auto-SNI Mode** | تشخیص خودکار CDN + انتخاب SNI بهینه |
| 📋 **Copy Top 5** | کپی ۵ آی‌پی برتر با یک کلیک |
| 💾 **Save to File** | ذخیره کامل نتایج در حافظه گوشی |
| 🚨 **Throttle Badge** | نمایش درصد افت سرعت روی هر آی‌پی |
| ⭐ **Grade System** | رتبه‌بندی S / A / B / C / D برای هر آی‌پی |
| 🌙 **Dark UI** | رابط کاربری تاریک با تم Forest Green |

---

## 📲 نصب

```
1. دکمه "دانلود APK" را بزنید
2. فایل app-release.apk را باز کنید
3. گزینه Install را انتخاب کنید
   (اگر پیام "منبع ناشناخته" داد → تنظیمات → مجوز نصب از منابع ناشناخته)
```

---

## 🚀 شروع کار

**۱. آی‌پی‌های خود را وارد کنید**
```
1.1.1.1
104.16.0.1
8.8.8.8
```

**۲. حالت اسکن را انتخاب کنید**
- `Simple` — سریع، برای تست اولیه
- `Auto-SNI` — دقیق، برای یافتن بهترین‌ها

**۳. Start Scan را بزنید و نتایج را ببینید**

---

## 📦 مشخصات فنی

| مشخصه | مقدار |
|--------|--------|
| Platform | Android 5.0+ |
| Framework | Flutter / Dart |
| Protocol | TLS 1.2/1.3 over TCP:443 |
| Threads | 20 رشته موازی |
| Reliability Tries | 5 بار per IP |
| Test Duration | تا 5 ثانیه per IP |
| Throttle Threshold | افت 40%+ سرعت = Throttled |

---

<div align="center">

**📣 برای دریافت آخرین بروزرسانی و آی‌پی‌های جدید به کانال تلگرام ما جوین بشید**

[![Join Telegram](https://img.shields.io/badge/Join-@mmdrlx-blue?style=for-the-badge&logo=telegram)](https://t.me/mmdrlx)

<sub>Made with ❤️ by MidONe</sub>

</div>
