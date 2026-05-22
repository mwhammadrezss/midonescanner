[app]

# (str) Title of your application
title = MidONe Scanner

# (str) Package name
package.name = midonescanner

# (str) Package domain (needed for android packaging)
package.domain = org.midone

# (str) Source code directory
source.dir = .

# (list) Source files to include (extensions)
source.include_exts = py,png,jpg,kv,json

# (str) Application versioning
version = 1.0.2

# (list) Application requirements
requirements = python3==3.13.3,kivy==2.3.0,plyer,requests

# (str) Supported orientations
orientation = portrait

# (bool) Use fullscreen mode or not
fullscreen = 0

# ==========================================================
# Android specific configurations
# ==========================================================

# (num) Android API to use (Target 34)
android.api = 34

# (num) Minimum API your APK will support
android.minapi = 21

# (str) Android NDK version to use
android.ndk = 26b

# (bool) Auto-accept SDK license
android.accept_sdk_license = True

# (list) The Android architectures to build for
android.archs = arm64-v8a, armeabi-v7a

# (list) Permissions required by the app
android.permissions = INTERNET, VIBRATE

# (bool) Allow Android Backup System
android.allow_backup = True

# IMPORTANT: pin p4a to a commit that uses Python 3.13, not 3.14
p4a.branch = develop
p4a.source_dir =

# ==========================================================
# Build options
# ==========================================================

# (int) Log level (0 = error only, 1 = info, 2 = debug)
log_level = 2

# (int) Display warning if buildozer is run as root
warn_on_root = 1

[buildozer]

# (int) Log level for buildozer itself
log_level = 2
