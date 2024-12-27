import os
import socket
import time
import hashlib
import mimetypes
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ttkbootstrap as ttkb


class FileTransferApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Transfer App")
        self.geometry("600x400")
        self.style = ttkb.Style("darkly")
        self.selected_file = None
        self.mode = "receiver"
        self.receiver_ip = self.get_receiver_ip()
        self.init_ui()
        self.header_text = "No headers available."

    def init_ui(self):
        # Title Label
        title_label = ttk.Label(self, text="File Transfer App", style="primary.TLabel", font=("Helvetica", 16))
        title_label.pack(pady=10)

        # Mode Selection
        mode_frame = ttk.Frame(self)
        mode_frame.pack(pady=10, fill="x", padx=20)

        self.mode_var = tk.StringVar(value="receiver")
        sender_radio = ttk.Radiobutton(
            mode_frame, text="Sender", variable=self.mode_var, value="sender", command=self.toggle_mode
        )
        receiver_radio = ttk.Radiobutton(
            mode_frame, text="Receiver", variable=self.mode_var, value="receiver", command=self.toggle_mode
        )
        sender_radio.pack(side="left", padx=5)
        receiver_radio.pack(side="left", padx=5)

        # Receiver IP Input
        self.ip_label = ttk.Label(self, text="Receiver IP (Sender Mode):", state="disabled")
        self.ip_label.pack(pady=5, anchor="w", padx=20)

        self.ip_input = ttk.Entry(self, state="disabled")
        self.ip_input.pack(pady=5, fill="x", padx=20)

        # Port Input
        port_frame = ttk.Frame(self)
        port_frame.pack(pady=10, fill="x", padx=20)

        ttk.Label(port_frame, text="Port (Default: 5001):").pack(side="left")
        self.port_input = ttk.Entry(port_frame, width=10)
        self.port_input.insert(0, "5001")
        self.port_input.pack(side="left", padx=10)

        # File Selection Button
        self.file_button = ttk.Button(self, text="Choose File (Sender Mode)", state="disabled", command=self.choose_file)
        self.file_button.pack(pady=10, padx=20)

        # Start Button
        self.start_button = ttk.Button(self, text="Start", style="success.TButton", command=self.start_transfer)
        self.start_button.pack(pady=20)

        # Status Label
        self.status_label = ttk.Label(self, text=f"Status: Receiver IP: {self.receiver_ip}", style="info.TLabel")
        self.status_label.pack(pady=10, anchor="w", padx=20)

        # Header Window Button
        self.header_button = ttk.Button(self, text="View Headers", command=self.show_headers)
        self.header_button.pack(pady=5)

    def toggle_mode(self):
        self.mode = self.mode_var.get()
        if self.mode == "sender":
            self.ip_label.config(state="normal")
            self.ip_input.config(state="normal")
            self.file_button.config(state="normal")
            self.status_label.config(text="Status: Select a file and enter receiver's IP.")
        else:
            self.ip_label.config(state="disabled")
            self.ip_input.config(state="disabled")
            self.file_button.config(state="disabled")
            self.status_label.config(text=f"Status: Receiver IP: {self.receiver_ip}")

    def choose_file(self):
        file_path = filedialog.askopenfilename(title="Select File", filetypes=(("All Files", "*.*"),))
        if file_path:
            self.selected_file = file_path
            self.status_label.config(text=f"Selected File: {os.path.basename(file_path)}")

    def get_receiver_ip(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "Unavailable"

    def show_headers(self):
        header_window = tk.Toplevel(self)
        header_window.title("Header Display")
        header_window.geometry("500x300")
        header_label = ttk.Label(header_window, text=self.header_text, wraplength=480, justify="left")
        header_label.pack(pady=10, padx=10)

    def detect_content_type(self, file_path):
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type or "application/octet-stream"

    def create_header(self, file_path):
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        source_ip = socket.gethostbyname(socket.gethostname())
        destination_ip = self.ip_input.get() if self.mode == "sender" else "0.0.0.0"
        timestamp = int(time.time())
        protocol_version = "1.0"
        content_type = self.detect_content_type(file_path)
        transfer_id = hashlib.md5(f"{file_name}{timestamp}".encode()).hexdigest()
        checksum = hashlib.md5(open(file_path, "rb").read()).hexdigest()
        sender_port = 5001
        receiver_port = int(self.port_input.get())

        header = (
            f"{file_name};{file_size};{source_ip};{destination_ip};{timestamp};{protocol_version};"
            f"{content_type};{transfer_id};{checksum};{sender_port};{receiver_port}"
        ).ljust(256)

        # Display header with field names
        self.header_text = (
            f"File Name: {file_name}\n"
            f"File Size: {file_size} bytes\n"
            f"Source IP: {source_ip}\n"
            f"Destination IP: {destination_ip}\n"
            f"Timestamp: {datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"Protocol Version: {protocol_version}\n"
            f"Content Type: {content_type}\n"
            f"Transfer ID: {transfer_id}\n"
            f"Checksum: {checksum}\n"
            f"Sender Port: {sender_port}\n"
            f"Receiver Port: {receiver_port}\n"
        )
        return header.encode()

    def parse_header(self, header):
        header_str = header.decode().strip()
        fields = header_str.split(";")
        file_name = fields[0]
        file_size = int(fields[1])
        source_ip = fields[2]
        destination_ip = fields[3]
        timestamp = int(fields[4])
        protocol_version = fields[5]
        content_type = fields[6]
        transfer_id = fields[7]
        checksum = fields[8]
        sender_port = int(fields[9])
        receiver_port = int(fields[10])

        readable_date = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
        self.header_text = (
            f"File Name: {file_name}\n"
            f"File Size: {file_size} bytes\n"
            f"Source IP: {source_ip}\n"
            f"Destination IP: {destination_ip}\n"
            f"Timestamp: {readable_date}\n"
            f"Protocol Version: {protocol_version}\n"
            f"Content Type: {content_type}\n"
            f"Transfer ID: {transfer_id}\n"
            f"Checksum: {checksum}\n"
            f"Sender Port: {sender_port}\n"
            f"Receiver Port: {receiver_port}\n"
        )
        return file_name

    def send_file(self):
        if not self.selected_file:
            self.status_label.config(text="Error: No file selected.")
            return

        encrypted_file = self.encrypt_file(self.selected_file)
        header = self.create_header(self.selected_file)
        server_ip = self.ip_input.get()
        server_port = int(self.port_input.get())

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((server_ip, server_port))
                s.sendall(header)
                with open(encrypted_file, "rb") as f:
                    s.sendall(f.read())
            self.status_label.config(text="File sent successfully!")
        except Exception as e:
            self.status_label.config(text=f"Error: {e}")
        finally:
            os.remove(encrypted_file)

    def receive_file(self):
        server_port = int(self.port_input.get())
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind(("0.0.0.0", server_port))
                server_socket.listen(1)
                self.status_label.config(text=f"Waiting for connection... (Receiver IP: {self.receiver_ip})")

                client_socket, _ = server_socket.accept()
                with client_socket:
                    header = client_socket.recv(256)
                    file_name = self.parse_header(header)

                    encrypted_file = "received_file.enc"
                    with open(encrypted_file, "wb") as f:
                        while True:
                            data = client_socket.recv(1024)
                            if not data:
                                break
                            f.write(data)

                    self.decrypt_file(encrypted_file, file_name)
                    os.remove(encrypted_file)
                    self.status_label.config(text=f"File '{file_name}' received and decrypted.")
        except Exception as e:
            self.status_label.config(text=f"Error: {e}")

    def encrypt_file(self, file_path):
        key = b"16byteencryption"
        iv = b"1234567890123456"
        cipher = AES.new(key, AES.MODE_CBC, iv)
        with open(file_path, "rb") as f:
            plaintext = f.read()
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        encrypted_file = f"{file_path}.enc"
        with open(encrypted_file, "wb") as f:
            f.write(ciphertext)
        return encrypted_file

    def decrypt_file(self, encrypted_file, output_file):
        key = b"16byteencryption"
        iv = b"1234567890123456"
        cipher = AES.new(key, AES.MODE_CBC, iv)
        with open(encrypted_file, "rb") as f:
            ciphertext = f.read()
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        with open(output_file, "wb") as f:
            f.write(plaintext)

    def start_transfer(self):
        if self.mode == "sender":
            threading.Thread(target=self.send_file).start()
        elif self.mode == "receiver":
            threading.Thread(target=self.receive_file).start()


if __name__ == "__main__":
    app = FileTransferApp()
    app.mainloop()
