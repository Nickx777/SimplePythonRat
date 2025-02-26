Introduction

This project is a Remote Access Tool (RAT) written in Python. It includes both the server (GUI) and the client in a single file. The server side runs a customtkinter GUI where you can manage and control multiple connected clients. The client side, once compiled, can connect back to the server, providing various functionalities like remote shell, file management, keylogging, screenshots, and more.


![Screenshot 2025-02-28 195728](https://github.com/user-attachments/assets/89f2e38c-50dd-4b32-a649-ff804cb507d9)

Important: This software is intended for educational and testing purposes only. Use it only on systems and networks you own or have explicit permission to test.

![Screenshot 2025-02-28 195735](https://github.com/user-attachments/assets/54b7f660-309d-4b92-ba37-99ba27ee7e04)


Features
Reverse Shell – Execute shell commands on the client machine.

Keylogger – Start/stop a keylogger and retrieve typed keystrokes in real-time.

Screenshot – Capture a screenshot of the client’s screen.

Live Screen – Stream the client’s screen as JPEG images in near real-time.

File Manager – Browse directories, download and upload files from/to the client.

Live Chat – Chat directly with the client via a GUI window on both sides.

Webcam Photo – Take a snapshot from the client’s webcam (if available).

Microphone Streaming – Capture audio from the client’s microphone in real-time.

Desktop Audio Streaming – Capture the client’s desktop audio output (if supported).

Startup Persistence – Add/remove registry entries to auto-run the client on Windows.

Shutdown / Disconnect – Remotely shut down or disconnect the client.

Multi-Port Listening – Server can listen on multiple ports simultaneously.

Requirements
Server-Side (Your Computer)

Python 3.7+ (Recommended 3.9 or newer)

Pip packages:

customtkinter

pillow (PIL)

pycryptodome

pyinstaller (for building the client)

pyaudio (if you plan to test audio streaming on the server side)

opencv-python (optional, but needed if you want to test client’s webcam features from the server side—though typically it’s the client that needs opencv-python)

Install these packages using:

	pip install customtkinter pillow pycryptodome pyinstaller pyaudio opencv-python
(You can omit pyaudio or opencv-python if you don’t need to test streaming from your server machine. The client side is the one that truly needs them to run those features.)



Client-Side (Target Machine)
The generated EXE will include all dependencies if you used PyInstaller.
If running the raw Python script (not recommended for stealth), it needs:

Python 3.7+

pillow (PIL)

pycryptodome

keyboard

opencv-python (for webcam features)

pyaudio (for microphone or desktop audio streaming)

pyttsx3 (for text-to-speech)

winreg (only on Windows, for startup persistence)

Installation and Setup

Clone or Download the repository containing the RATApp code.

Install Dependencies on your server machine:


	pip install customtkinter pillow pycryptodome pyinstaller pyaudio opencv-python
 
Run the server code (e.g., python rat.py) – it will open a customtkinter GUI.



Generating the Client EXE

Open the Client Generator tab in the RAT GUI.

Fill in:
Server IP: The public or local IP address of the server (e.g., 127.0.0.1 for testing, or your public IP if over the internet).

Port: The port you plan to listen on (default 4444).

(Optional) Enable Persistence: If checked, the client will automatically attempt to reconnect every X seconds.

(Optional) Reconnect Delay: If persistence is checked, the delay is how often it tries to reconnect (default 30 seconds).

Client/Exe Name: The final name for the generated executable (e.g., myrat).

(Optional) Hidden: Generate as a .pyw (no console window) and build with PyInstaller’s --windowed flag.

Click Choose Save Directory to select where the final EXE will be placed.

Click Generate Client EXE.

The tool will generate the .py or .pyw file in that folder, then run PyInstaller to create the .exe.

When it finishes, you should see myrat.exe (or your chosen name) in the specified directory.



Starting the Server

In the Server tab of the GUI:

Listen IP: Usually 0.0.0.0 to accept connections on all interfaces.

Listen Port(s): Provide one or more ports, comma-separated (e.g., 4444 or 4444,5555).

Click Start Server.

The server console should say Listening on <port> for each port.

Distribute or run the client EXE on the target machine.

If it can reach your server IP:port, you’ll see a new client appear in the RAT GUI’s dropdown list.

Using the Control Panel

Once the server is listening and a client connects, select the client from the Select a Client dropdown in the Control Panel tab. You can now use any of the following features:



Keylogger
Click Keylogger.

A new window opens, and it immediately sends start_keylog to the client.
The window will periodically fetch logs (get_keylog) and display them in the textbox.
Close the window to stop the keylogger. The code sends stop_keylog.

Screenshot
Click Screenshot.

The server sends the screenshot command to the client (not shell screenshot).
If successful, a new window displays the captured image.

Live Screen
Click Live Screen.

A window appears with a label for Quality and FPS.
Adjust these sliders:
Quality (10–100): Higher means better image quality but larger data.
FPS (1–50): Higher means more frequent updates but more bandwidth.
The server continuously sends live_screen_jpeg <quality> commands to the client, retrieving frames as base64.
Close the window to stop.

File Manager
Click File Manager.

A new window opens.
The top entry shows a path (e.g., C:\).
Go – Refreshes the file list for the current path.
Up – Moves one directory up.
Double-click a folder to open it; double-click a file to download it (you will be prompted where to save).
To upload a file, go back to the Control Panel and use Upload File. Provide a local file path and the remote path.

Live Chat
Click Live Chat.

A chat window opens.
Type a message and press Send. The client will receive and display it if their chat window is open.
On the client side, once chat_on is triggered, a chat window appears. The client can reply, and you’ll see chat_input <message> on the server side.

Other Features
Send Message Box: Pops up a message box on the client’s screen.
Shutdown Client: Attempts to shut down the client’s system (shutdown /s /t 0).
Add to Startup / Remove from Startup: Creates or deletes a registry key to make the client run at startup.
Webcam Photo: Grabs a single frame from the client’s default webcam.
Live Mic: Streams short audio segments from the client’s microphone.
Live Desktop Audio: Streams short audio segments from the client’s desktop output (depends on system audio loopback availability).
Tips and Troubleshooting
Network Connectivity:

Ensure your router/firewall allows inbound connections on the port(s) you choose.
If testing locally, use 127.0.0.1 or localhost.
Permissions:

On Windows, some features (like registry edits, shutdown, or capturing mic/desktop audio) may require elevated privileges or special drivers.
Antivirus/Firewall:

RATs are often flagged by antivirus. This code is for educational usage. If you’re testing on your own system, you may need to whitelist the generated EXE.
Keylogger Issues:

The client uses the keyboard module, which sometimes conflicts with certain Windows security settings. Make sure the client has permissions to capture keystrokes.
Screenshot Command:

Do not type shell screenshot. That will attempt to run screenshot in the Windows shell and fail. Use the built-in RAT command: screenshot.
Multiple Ports:

You can listen on multiple ports by entering them comma-separated in the Listen Port(s) field. Each port spawns a separate thread.
Rebuilding the Client:

If you change the code or want different settings, generate a new client EXE with the updated settings.
Persistence:

If you enable auto-reconnect (persistence), the client will keep trying to connect every X seconds if the connection fails or is refused.
Encryption:

Communication is encrypted using AES with a fixed key and IV. For real security, you’d want dynamic key exchange, but for a demonstration, this suffices.
Disclaimer

This project is provided for educational and testing purposes only.
Use it legally and ethically on systems you own or have permission to test.
The author(s) assume no responsibility for any misuse or damages.
