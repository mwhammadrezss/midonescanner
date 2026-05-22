[app]
title = MidONe Scanner SK
package.name = midone_scanner
package.domain = org.mmdrlx
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0

# اگر کتابخانه دیگری مثل requests در کد پایتون استفاده کردی، اینجا اضافه کن
# مثلا: requirements = python3,kivy,requests
requirements = python3,kivy

orientation = portrait
fullscreen = 0
android.permissions = INTERNET
android.api = 34
android.minapi = 26
android.ndk = 25b
android.archs = arm64-v8a

# این خط برای گیت‌هاب اکشنز فوق‌العاده ضروری است
android.accept_sdk_license = True

[buildozer]
log_level = 2
