[app]

title = MidONe Scanner SK
package.name = midonescanner
package.domain = org.mmdrlx
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json
source.main = main.py
version = 6.1
android.numeric_version = 610

requirements = python3,kivy==2.3.0,cython==3.0.11

orientation = portrait
fullscreen = 0

android.api = 33
android.minapi = 21
android.ndk = 25b
android.ndk_api = 21
android.sdk = 33
android.accept_sdk_license = True
android.arch = arm64-v8a
android.logcat_filters = *:S python:D
android.copy_libs = 1
android.enable_androidx = True
android.permissions = INTERNET,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE

[buildozer]
log_level = 2
warn_on_root = 1
