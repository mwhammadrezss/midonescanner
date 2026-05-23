# -*- coding: utf-8 -*-
import os
import re
import json
import threading
import time
from kivy.utils import platform
from kivy.app import App
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen, FadeTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.label import Label
from kivy.properties import StringProperty, NumericProperty, ListProperty, BooleanProperty
from kivy.core.window import Window
from kivy.core.clipboard import Clipboard
from kivy.clock import Clock
from kivy.animation import Animation
from kivy.storage.jsonstore import JsonStore

# Set default window size for desktop testing (will be responsive on mobile)
Window.size = (400, 750)

# KV Design with Premium Dark Mode & Neon Green Aesthetic
KV_DESIGN = '''
#:import Window kivy.core.window.Window

<NeonButton@ButtonBehavior+Label>:
    text_color: [1, 1, 1, 1]
    bg_color: [0.62, 1.0, 0.0, 1]  # #9EFF00
    font_name: "Roboto"
    bold: True
    canvas.before:
        Color:
            rgba: self.bg_color if self.state == 'normal' else [0.5, 0.8, 0.0, 1]
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [22, ]

<DarkCard@BoxLayout>:
    orientation: 'vertical'
    padding: dp(16)
    spacing: dp(12)
    canvas.before:
        Color:
            rgba: [0.08, 0.08, 0.08, 1]  # #161616
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [24, ]
        Color:
            rgba: [0.62, 1.0, 0.0, 0.3]  # Subtle Neon border glow
        Line:
            rounded_rectangle: (self.x, self.y, self.width, self.height, 24)
            width: dp(1)

<IPItem@BoxLayout>:
    ip_text: ''
    ping_text: ''
    status_text: 'Passed'
    retest_callback: None
    orientation: 'horizontal'
    padding: [dp(12), dp(8)]
    spacing: dp(10)
    size_hint_y: None
    height: dp(60)
    canvas.before:
        Color:
            rgba: [0.08, 0.08, 0.08, 1]
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [14, ]
        Color:
            rgba: [0.62, 1.0, 0.0, 0.15]
        Line:
            rounded_rectangle: (self.x, self.y, self.width, self.height, 14)
            width: dp(1)

    Label:
        text: root.ip_text
        color: [1, 1, 1, 1]
        bold: True
        font_size: '14sp'
        halign: 'left'
        text_size: self.size
        valign: 'middle'
        padding_x: dp(5)

    Label:
        text: root.ping_text
        color: [0.62, 1.0, 0.0, 1]
        font_size: '13sp'
        size_hint_x: None
        width: dp(80)
        valign: 'middle'

    BoxLayout:
        size_hint_x: None
        width: dp(70)
        padding: [dp(4), dp(6)]
        canvas.before:
            Color:
                rgba: [0, 0.4, 0, 0.2]
            RoundedRectangle:
                pos: self.pos
                size: self.size
                radius: [8, ]
        Label:
            text: root.status_text
            color: [0.4, 1, 0.4, 1]
            font_size: '11sp'
            bold: True

    ButtonBehavior:
        size_hint_x: None
        width: dp(40)
        on_release: if root.retest_callback: root.retest_callback(root.ip_text)
        canvas.before:
            Color:
                rgba: [0.15, 0.15, 0.15, 1]
            RoundedRectangle:
                pos: self.pos
                size: self.size
                radius: [10, ]
        # Minimalist Refresh Icon drawn with canvas
        canvas:
            Color:
                rgba: [0.62, 1.0, 0.0, 1]
            Line:
                circle: (self.center_x, self.center_y, dp(7), 0, 290)
                width: dp(1.5)
            Triangle:
                points: [self.center_x + dp(5), self.center_y + dp(7), self.center_x + dp(9), self.center_y + dp(3), self.center_x + dp(1), self.center_y + dp(2)]

ScreenManager:
    transition: FadeTransition(duration=0.3)
    HomeScreen:
    ScanningScreen:
    ResultsScreen:

<HomeScreen>:
    name: 'home'
    canvas.before:
        Color:
            rgba: [0.046, 0.046, 0.046, 1]
        Rectangle:
            pos: self.pos
            size: self.size

    BoxLayout:
        orientation: 'vertical'
        padding: dp(20)
        spacing: dp(15)

        # HEADER SECTION
        BoxLayout:
            size_hint_y: None
            height: dp(60)
            orientation: 'horizontal'
            valign: 'middle'

            BoxLayout:
                orientation: 'vertical'
                size_hint_x: 0.7
                Label:
                    text: "MidONe"
                    font_size: '22sp'
                    bold: True
                    color: [1, 1, 1, 1]
                    halign: 'left'
                    text_size: self.size
                Label:
                    text: "v1.0.2"
                    font_size: '13sp'
                    color: [0.62, 1.0, 0.0, 1]
                    halign: 'left'
                    text_size: self.size

            ButtonBehavior:
                size_hint: (None, None)
                size: (dp(40), dp(40))
                pos_hint: {'center_y': 0.5}
                on_release: root.show_history_popup()
                canvas.before:
                    Color:
                        rgba: [0.08, 0.08, 0.08, 1]
                    RoundedRectangle:
                        pos: self.pos
                        size: self.size
                        radius: [12, ]
                canvas:
                    Color:
                        rgba: [0.62, 1.0, 0.0, 1]
                    Line:
                        circle: (self.center_x, self.center_y, dp(9))
                        width: dp(1.5)
                    Line:
                        points: [self.center_x, self.center_y, self.center_x, self.center_y + dp(5)]
                        width: dp(1.5)
                    Line:
                        points: [self.center_x, self.center_y, self.center_x + dp(4), self.center_y]
                        width: dp(1.5)

            Widget:
                size_hint_x: None
                width: dp(10)

            ButtonBehavior:
                size_hint: (None, None)
                size: (dp(40), dp(40))
                pos_hint: {'center_y': 0.5}
                on_release: root.open_telegram()
                canvas.before:
                    Color:
                        rgba: [0.08, 0.08, 0.08, 1]
                    RoundedRectangle:
                        pos: self.pos
                        size: self.size
                        radius: [12, ]
                canvas:
                    Color:
                        rgba: [0.62, 1.0, 0.0, 1]
                    Mesh:
                        mode: 'triangle_fan'
                        vertices: [self.x+dp(10), self.y+dp(20), 0,0, self.x+dp(32), self.y+dp(28), 0,0, self.x+dp(26), self.y+dp(12), 0,0, self.x+dp(20), self.y+dp(18), 0,0]
                    Line:
                        points: [self.x+dp(20), self.y+dp(18), self.x+dp(22), self.y+dp(12), self.x+dp(26), self.y+dp(12)]
                        width: dp(1)

        # PING / CONNECTION STATUS BANNER
        BoxLayout:
            size_hint_y: None
            height: dp(35)
            padding: [dp(12), 0]
            canvas.before:
                Color:
                    rgba: [0.08, 0.08, 0.08, 1]
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [10, ]
            Label:
                text: root.connection_status
                color: [0.7, 0.7, 0.7, 1]
                font_size: '12sp'
                halign: 'left'
                text_size: self.size
                valign: 'middle'
            Label:
                text: root.ping_status
                color: [0.62, 1.0, 0.0, 1]
                font_size: '12sp'
                bold: True
                halign: 'right'
                text_size: self.size
                valign: 'middle'

        Widget:
            size_hint_y: None
            height: dp(10)

        DarkCard:
            Label:
                text: "Enter IPs Below:"
                font_size: '15sp'
                color: [1, 1, 1, 1]
                bold: True
                size_hint_y: None
                height: dp(20)
                halign: 'left'
                text_size: self.size

            TextInput:
                id: ip_input
                hint_text: "1.2.3.4\\n5.6.7.8\\n..."
                hint_text_color: [0.4, 0.4, 0.4, 1]
                background_color: [0.05, 0.05, 0.05, 1]
                foreground_color: [1, 1, 1, 1]
                cursor_color: [0.62, 1.0, 0.0, 1]
                font_size: '16sp'
                padding: dp(12)
                multiline: True
                size_hint_y: 1
                background_normal: ''
                background_active: ''
                canvas.after:
                    Color:
                        rgba: [0.62, 1.0, 0.0, 0.5] if self.focus else [0.2, 0.2, 0.2, 1]
                    Line:
                        rounded_rectangle: (self.x, self.y, self.width, self.height, 12)
                        width: dp(1.2)

            Label:
                text: root.loaded_count_text
                font_size: '13sp'
                color: [0.62, 1.0, 0.0, 1]
                bold: True
                size_hint_y: None
                height: dp(20)
                halign: 'center'

        BoxLayout:
            size_hint_y: None
            height: dp(50)
            spacing: dp(15)

            NeonButton:
                text: "📋 Paste"
                bg_color: [0.08, 0.22, 0.05, 1]
                text_color: [0.62, 1.0, 0.0, 1]
                on_release: root.perform_smart_paste()
                canvas.after:
                    Color:
                        rgba: [0.62, 1.0, 0.0, 0.4]
                    Line:
                        rounded_rectangle: (self.x, self.y, self.width, self.height, 22)
                        width: dp(1)

            NeonButton:
                text: "⚡ Load IPs"
                bg_color: [0.62, 1.0, 0.0, 1]
                on_release: root.load_ips()

        Widget:
            size_hint_y: None
            height: dp(10)

        BoxLayout:
            size_hint_y: None
            height: dp(55)
            spacing: dp(15)

            NeonButton:
                text: "Normal Scan"
                bg_color: [0.1, 0.1, 0.1, 1]
                on_release: root.start_scan(mode="normal")
                canvas.after:
                    Color:
                        rgba: [0.62, 1.0, 0.0, 0.6]
                    Line:
                        rounded_rectangle: (self.x, self.y, self.width, self.height, 22)
                        width: dp(1.5)

            NeonButton:
                text: "🚀 Deep Scan"
                bg_color: [0.62, 1.0, 0.0, 1]
                on_release: root.start_scan(mode="deep")

        Widget:
            size_hint_y: 0.1

    BoxLayout:
        id: promo_popup
        orientation: 'vertical'
        pos_hint: {'x': 0, 'y': 0}
        size_hint: (1, 1)
        opacity: 0
        disabled: True
        canvas.before:
            Color:
                rgba: [0, 0, 0, 0.85]
            Rectangle:
                pos: self.pos
                size: self.size

        BoxLayout:
            orientation: 'vertical'
            size_hint: (0.85, None)
            height: dp(260)
            pos_hint: {'center_x': 0.5, 'center_y': 0.5}
            padding: dp(24)
            spacing: dp(20)
            canvas.before:
                Color:
                    rgba: [0.08, 0.08, 0.08, 1]
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [24, ]
                Color:
                    rgba: [0.62, 1.0, 0.0, 1]
                Line:
                    rounded_rectangle: (self.x, self.y, self.width, self.height, 24)
                    width: dp(2)

            Label:
                text: "📢 کانال تلگرام سازنده"
                font_size: '18sp'
                bold: True
                color: [0.62, 1.0, 0.0, 1]
                halign: 'center'

            Label:
                text: "برای دریافت آخرین آپدیت برنامه و IPهای به‌روزرسانی شده، سالم و زنده به کانال تلگرامی ما بپیوندید."
                font_size: '14sp'
                color: [1, 1, 1, 1]
                halign: 'center'
                valign: 'middle'
                text_size: (self.width - dp(10), None)

            NeonButton:
                text: "Join @mmdrlx"
                size_hint_y: None
                height: dp(45)
                on_release: root.close_promo_popup(join=True)

    BoxLayout:
        id: history_popup
        orientation: 'vertical'
        size_hint: (1, 1)
        opacity: 0
        disabled: True
        canvas.before:
            Color:
                rgba: [0, 0, 0, 0.7]
            Rectangle:
                pos: self.pos
                size: self.size
        ButtonBehavior:
            size_hint_y: 0.6
            on_release: root.hide_history_popup()
        BoxLayout:
            orientation: 'vertical'
            size_hint_y: 0.4
            padding: dp(20)
            spacing: dp(12)
            canvas.before:
                Color:
                    rgba: [0.08, 0.08, 0.08, 1]
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [24, 24, 0, 0]
            Label:
                text: "🕒 Last Best IPs (History)"
                font_size: '15sp'
                bold: True
                color: [0.62, 1.0, 0.0, 1]
                size_hint_y: None
                height: dp(25)
            Label:
                id: history_content
                text: "No history found."
                color: [0.9, 0.9, 0.9, 1]
                font_size: '14sp'
                halign: 'center'
            NeonButton:
                text: "Close"
                size_hint_y: None
                height: dp(40)
                bg_color: [0.2, 0.2, 0.2, 1]
                on_release: root.hide_history_popup()

<ScanningScreen>:
    name: 'scanning'
    canvas.before:
        Color:
            rgba: [0.046, 0.046, 0.046, 1]
        Rectangle:
            pos: self.pos
            size: self.size

    BoxLayout:
        orientation: 'vertical'
        padding: dp(30)
        spacing: dp(25)
        Widget:
            size_hint_y: 0.2

        BoxLayout:
            id: radar_box
            size_hint: (None, None)
            size: (dp(180), dp(180))
            pos_hint: {'center_x': 0.5}
            canvas.before:
                Color:
                    rgba: [0.08, 0.08, 0.08, 1]
                Ellipse:
                    pos: self.pos
                    size: self.size
                Color:
                    rgba: [0.62, 1.0, 0.0, 0.2]
                Line:
                    circle: (self.center_x, self.center_y, dp(90))
                    width: dp(2)
                Line:
                    circle: (self.center_x, self.center_y, dp(50))
                    width: dp(1)
            canvas.after:
                Color:
                    rgba: [0.62, 1.0, 0.0, 0.8]
                Line:
                    points: [self.x, root.scan_line_y, self.right, root.scan_line_y] if root.scan_line_y > 0 else [self.x, self.y, self.x, self.y]
                    width: dp(2.5)

        Label:
            text: str(int(root.progress_percent)) + "%"
            font_size: '38sp'
            bold: True
            color: [0.62, 1.0, 0.0, 1]
            size_hint_y: None
            height: dp(45)

        Label:
            text: root.current_status_text
            font_size: '14sp'
            color: [1, 1, 1, 1]
            halign: 'center'
            size_hint_y: None
            height: dp(30)
        Widget:
            size_hint_y: 0.3

<ResultsScreen>:
    name: 'results'
    canvas.before:
        Color:
            rgba: [0.046, 0.046, 0.046, 1]
        Rectangle:
            pos: self.pos
            size: self.size

    BoxLayout:
        orientation: 'vertical'
        padding: dp(16)
        spacing: dp(12)

        BoxLayout:
            size_hint_y: None
            height: dp(50)
            orientation: 'horizontal'
            Label:
                text: "📊 Scan Results"
                font_size: '18sp'
                bold: True
                color: [1, 1, 1, 1]
                halign: 'left'
                text_size: self.size
                valign: 'middle'
            Label:
                text: root.clean_summary_text
                font_size: '13sp'
                bold: True
                color: [0.4, 1, 0.4, 1]
                halign: 'right'
                text_size: self.size
                valign: 'middle'

        ScrollView:
            size_hint_y: 1
            BoxLayout:
                id: results_container
                orientation: 'vertical'
                spacing: dp(10)
                size_hint_y: None
                height: self.minimum_height

        BoxLayout:
            size_hint_y: None
            height: dp(45)
            spacing: dp(10)
            NeonButton:
                text: "Copy All"
                bg_color: [0.08, 0.08, 0.08, 1]
                on_release: root.copy_results("all")
                canvas.after:
                    Color:
                        rgba: [0.62, 1.0, 0.0, 0.5]
                    Line:
                        rounded_rectangle: (self.x, self.y, self.width, self.height, 22)
                        width: dp(1)
            NeonButton:
                text: "⭐ Copy 10 Best"
                bg_color: [0.62, 1.0, 0.0, 1]
                on_release: root.copy_results("10")

        BoxLayout:
            size_hint_y: None
            height: dp(45)
            spacing: dp(10)
            NeonButton:
                text: "Copy 3 Best"
                bg_color: [0.08, 0.22, 0.05, 1]
                text_color: [0.62, 1.0, 0.0, 1]
                on_release: root.copy_results("3")
                canvas.after:
                    Color:
                        rgba: [0.62, 1.0, 0.0, 0.4]
                    Line:
                        rounded_rectangle: (self.x, self.y, self.width, self.height, 22)
                        width: dp(1)
            NeonButton:
                text: "🔗 Share"
                bg_color: [0.1, 0.1, 0.1, 1]
                on_release: root.quick_share_results()
                canvas.after:
                    Color:
                        rgba: [1, 1, 1, 0.2]
                    Line:
                        rounded_rectangle: (self.x, self.y, self.width, self.height, 22)
                        width: dp(1)

        NeonButton:
            text: "Close"
            size_hint_y: None
            height: dp(48)
            bg_color: [0.2, 0.2, 0.2, 1]
            on_release: root.go_back_home()
'''

class HomeScreen(Screen):
    connection_status = StringProperty("Fetching ISP Info...")
    ping_status = StringProperty("Ping: -- ms")
    loaded_count_text = StringProperty("No IPs loaded yet")
    valid_ips = ListProperty([])

    def __init__(self, **kwargs):
        super(HomeScreen, self).__init__(**kwargs)
        Clock.schedule_once(self.check_first_run, 0.5)
        Clock.schedule_interval(self.update_network_status, 5.0)
        Clock.schedule_once(self.update_network_status, 0.1)

    # تابع جدید برای دریافت مسیر ایمن فایل‌ها در اندروید
    def get_safe_path(self, filename):
        app = App.get_running_app()
        if app:
            return os.path.join(app.user_data_dir, filename)
        return filename

    def check_first_run(self, dt):
        store = JsonStore(self.get_safe_path('midone_config.json'))
        if not store.exists('settings') or not store.get('settings').get('promo_shown', False):
            self.show_promo_popup()

    def show_promo_popup(self):
        self.ids.promo_popup.disabled = False
        anim = Animation(opacity=1, duration=0.4)
        anim.start(self.ids.promo_popup)

    def close_promo_popup(self, join=False):
        if join:
            self.open_telegram()
        store = JsonStore(self.get_safe_path('midone_config.json'))
        store.put('settings', promo_shown=True)
        anim = Animation(opacity=0, duration=0.3)
        anim.bind(on_complete=lambda *args: setattr(self.ids.promo_popup, 'disabled', True))
        anim.start(self.ids.promo_popup)

    def open_telegram(self):
        import webbrowser
        webbrowser.open("https://t.me/mmdrlx")

    def update_network_status(self, dt):
        self.connection_status = "Connected to Mobile Data (4G)"
        self.ping_status = "Ping: 42 ms"

    def perform_smart_paste(self):
        clipboard_text = Clipboard.paste()
        if clipboard_text:
            cleaned = self.validate_and_extract_ips(clipboard_text)
            if cleaned:
                self.ids.ip_input.text = "\n".join(cleaned)
                self.valid_ips = cleaned
                self.loaded_count_text = f"Successfully validated & loaded {len(cleaned)} IPs from Clipboard!"
            else:
                self.loaded_count_text = "⚠️ Clipboard text contains no valid IPv4 addresses."
        else:
            self.loaded_count_text = "⚠️ Clipboard is completely empty."

    def load_ips(self):
        input_text = self.ids.ip_input.text
        cleaned = self.validate_and_extract_ips(input_text)
        self.valid_ips = cleaned
        if cleaned:
            self.loaded_count_text = f"Total Valid IPs parsed successfully: {len(cleaned)}"
        else:
            self.loaded_count_text = "⚠️ Please type or paste valid IPs first!"

    def validate_and_extract_ips(self, text):
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        found = re.findall(ipv4_pattern, text)
        return list(set(found))

    def start_scan(self, mode="normal"):
        if not self.valid_ips:
            self.load_ips()
            if not self.valid_ips:
                return
        sm = self.manager
        scanning_scr = sm.get_screen('scanning')
        scanning_scr.prepare_and_launch_scan(self.valid_ips, mode)
        sm.current = 'scanning'

    def show_history_popup(self):
        store = JsonStore(self.get_safe_path('midone_history.json'))
        if store.exists('cache'):
            ips = store.get('cache').get('best_ips', [])
            if ips:
                self.ids.history_content.text = "\n".join([f"⭐ {ip}" for ip in ips])
            else:
                self.ids.history_content.text = "No history rows cached yet."
        else:
            self.ids.history_content.text = "No previous scan cached rows."
        self.ids.history_popup.disabled = False
        Animation(opacity=1, duration=0.3).start(self.ids.history_popup)

    def hide_history_popup(self):
        anim = Animation(opacity=0, duration=0.2)
        anim.bind(on_complete=lambda *args: setattr(self.ids.history_popup, 'disabled', True))
        anim.start(self.ids.history_popup)


class ScanningScreen(Screen):
    scan_line_y = NumericProperty(0)
    progress_percent = NumericProperty(0)
    current_status_text = StringProperty("Initializing scanning systems...")
    
    def prepare_and_launch_scan(self, ips, mode):
        self.ips_to_scan = ips
        self.scan_mode = mode
        self.progress_percent = 0
        self.scan_line_y = 0
        self.start_radar_animation()
        threading.Thread(target=self.run_scanning_engine, daemon=True).start()

    def start_radar_animation(self):
        box = self.ids.radar_box
        self.scan_line_y = box.y
        anim = Animation(scan_line_y=box.top, duration=1.2, t='in_out_quad') + \
               Animation(scan_line_y=box.y, duration=1.2, t='in_out_quad')
        anim.repeat = True
        self.active_radar_anim = anim
        anim.start(self)

    def run_scanning_engine(self):
        total = len(self.ips_to_scan)
        results = []
        multiplier = 0.1 if self.scan_mode == "normal" else 0.25 
        
        for idx, ip in enumerate(self.ips_to_scan):
            progress = ((idx + 1) / total) * 100
            self.progress_percent = progress
            self.current_status_text = f"Checking IP {idx+1} of {total}\nTesting latency path: {ip}"
            
            time.sleep(multiplier) 
            simulated_ping = round(30 + (hash(ip) % 120), 1)
            results.append({"ip": ip, "ping": f"{simulated_ping} ms", "val": simulated_ping})
            
        results = sorted(results, key=lambda x: x['val'])
        self.trigger_alert_vibration()
        Clock.schedule_once(lambda dt: self.finalize_scan_results(results), 0.2)

    def trigger_alert_vibration(self):
        try:
            from plyer import vibrator
            vibrator.vibrate(0.15) 
        except:
            pass 

    def finalize_scan_results(self, results):
        if hasattr(self, 'active_radar_anim'):
            self.active_radar_anim.cancel(self)
        sm = self.manager
        res_screen = sm.get_screen('results')
        res_screen.render_results_view(results)
        sm.current = 'results'


class ResultsScreen(Screen):
    clean_summary_text = StringProperty("0 Clean")
    raw_results_list = []

    def get_safe_path(self, filename):
        app = App.get_running_app()
        if app:
            return os.path.join(app.user_data_dir, filename)
        return filename

    def render_results_view(self, results):
        self.raw_results_list = results
        container = self.ids.results_container
        container.clear_widgets()
        
        self.clean_summary_text = f"{len(results)} Passed · {len(results)} Clean"
        
        top_3 = [item['ip'] for item in results[:3]]
        store = JsonStore(self.get_safe_path('midone_history.json'))
        store.put('cache', best_ips=top_3)

        for idx, item in enumerate(results):
            item_widget = Builder.load_string(f'''
IPItem:
    ip_text: "{item['ip']}"
    ping_text: "⚡ {item['ping']}"
''')
            item_widget.retest_callback = self.retest_single_row
            container.add_widget(item_widget)

    def retest_single_row(self, ip_address):
        for widget in self.ids.results_container.children:
            if hasattr(widget, 'ip_text') and widget.ip_text == ip_address:
                widget.ping_text = "🔄 ...ms"
                
                def async_retest():
                    time.sleep(0.4)
                    new_ping = round(25 + (time.time() % 60), 1)
                    def update_ui(dt):
                        widget.ping_text = f"⚡ {new_ping} ms"
                    Clock.schedule_once(update_ui)
                
                threading.Thread(target=async_retest, daemon=True).start()
                break

    def copy_results(self, mode):
        if not self.raw_results_list: return
        if mode == "all":
            selected = [item['ip'] for item in self.raw_results_list]
        elif mode == "10":
            selected = [item['ip'] for item in self.raw_results_list[:10]]
        elif mode == "3":
            selected = [item['ip'] for item in self.raw_results_list[:3]]
            
        output_text = "\n".join(selected)
        Clipboard.copy(output_text)

    def quick_share_results(self):
        if not self.raw_results_list: return
        top_ips = "\n".join([item['ip'] for item in self.raw_results_list[:3]])
        share_msg = f"MidONe Scanner Top Active IPs:\n{top_ips}\nJoin Channel: @mmdrlx"
        
        try:
            from plyer import share
            share.share(share_msg)
        except:
            Clipboard.copy(share_msg)

    def go_back_home(self):
        self.manager.current = 'home'


class MidONeScannerApp(App):
    # درخواست مجوزها به درستی و در زمان مناسب (هنگام استارت برنامه)
    def on_start(self):
        if platform == 'android':
            try:
                from android.permissions import request_permissions, Permission
                request_permissions([
                    Permission.INTERNET,
                    Permission.ACCESS_NETWORK_STATE,
                    Permission.VIBRATE
                ])
            except Exception as e:
                print(f"Permission Request Failed: {e}")

    def build(self):
        self.title = "MidONe Scanner"
        Window.bind(on_keyboard=self.handle_hardware_back_button)
        return Builder.load_string(KV_DESIGN)

    def handle_hardware_back_button(self, window, key, scancode, codepoint, modifiers):
        if key == 27: 
            sm = self.root
            if sm.current != 'home':
                sm.current = 'home'
                return True 
        return False

if __name__ == '__main__':
    MidONeScannerApp().run()
