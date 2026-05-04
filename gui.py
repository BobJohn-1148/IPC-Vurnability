"""
gui.py — IPC Buffer Overflow Demo (GUI)
Requires: Python 3, tkinter (standard library), gcc (Linux)

Before running:
  gcc -o server      server.c
  gcc -fno-stack-protector -z execstack -no-pie -o server_vuln server_vuln.c
  gcc -o client      client.c
  python3 gui.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import threading
import socket
import struct
import os
import signal
import re

# ── constants matching the C code ──────────────────────────────────────────
SAFE_SOCKET_PATH  = "/tmp/ipc_demo_socket"
VULN_SOCKET_PATH  = "/tmp/ipc_vuln_socket"
CMD_SIZE          = 16
PAYLOAD_SIZE      = 128
LOCAL_BUF_SIZE    = 32   # server's small stack buffer — overflow threshold


# ── IPC helpers ────────────────────────────────────────────────────────────

def make_ipc_message(command: str, payload: str) -> bytes:
    """Pack a command + payload into the IPCMessage struct layout."""
    cmd_bytes     = command.encode()[:CMD_SIZE - 1].ljust(CMD_SIZE,  b'\x00')
    payload_bytes = payload.encode()[:PAYLOAD_SIZE - 1].ljust(PAYLOAD_SIZE, b'\x00')
    return cmd_bytes + payload_bytes


def send_message(socket_path: str, command: str, payload: str) -> str:
    """Connect to the Unix socket server, send a message, return response."""
    msg = make_ipc_message(command, payload)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(socket_path)
            s.sendall(msg)
            response = s.recv(256)
            return response.decode(errors="replace").rstrip('\x00')
    except FileNotFoundError:
        return "ERROR: Server socket not found — is the server running?"
    except ConnectionRefusedError:
        return "ERROR: Connection refused — server may have crashed."
    except socket.timeout:
        return "ERROR: Timed out waiting for server response."
    except Exception as e:
        return f"ERROR: {e}"


# ── server process management ──────────────────────────────────────────────

class ServerManager:
    def __init__(self):
        self._proc           = None
        self._mode           = None
        self.buffer_address  = None   # parsed from server stdout
        self._stdout_lines   = []     # all output lines captured
        self._lock           = threading.Lock()

    def start(self, mode: str) -> str:
        self.stop()
        self.buffer_address = None
        with self._lock:
            self._stdout_lines.clear()

        binary = "./server_vuln" if mode == "vulnerable" else "./server"
        if not os.path.exists(binary):
            return (
                f"Binary '{binary}' not found. Compile first:\n" +
                ("  gcc -fno-stack-protector -z execstack -no-pie -o server_vuln server_vuln.c"
                 if mode == "vulnerable" else
                 "  gcc -o server server.c")
            )
        try:
            self._proc = subprocess.Popen(
                [binary],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            self._mode = mode
            t = threading.Thread(target=self._read_stdout, daemon=True)
            t.start()
            return f"[server] Started ({mode} mode) — PID {self._proc.pid}"
        except Exception as e:
            return f"ERROR starting server: {e}"

    def _read_stdout(self):
        """Read server stdout line-by-line, parse buffer address."""
        if not self._proc:
            return
        for line in self._proc.stdout:
            line = line.rstrip()
            with self._lock:
                self._stdout_lines.append(line)
            # Parse: "local_buffer is at address: 0x7ffd..."
            m = re.search(r"local_buffer is at address:\s*(0x[0-9a-fA-F]+)", line)
            if m:
                self.buffer_address = m.group(1)

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc        = None
        self._mode        = None
        self.buffer_address = None

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def has_crashed(self) -> bool:
        """True if the process was running but has now exited unexpectedly."""
        return self._proc is not None and self._proc.poll() is not None

    @property
    def mode(self):
        return self._mode


server_mgr = ServerManager()


# ── GUI ────────────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IPC Buffer Overflow Demo")
        self.resizable(False, False)
        self.configure(bg="#1e1e2e")
        self._vcmd = (self.register(self._validate_payload_len), '%P')
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_buffer_address()   # start address polling loop

    # ── layout ──────────────────────────────────────────────────────────

    def _build_ui(self):
        PAD = {"padx": 12, "pady": 6}

        # ── title bar ───────────────────────────────────────────────────
        title_frame = tk.Frame(self, bg="#313244", pady=8)
        title_frame.pack(fill="x")
        tk.Label(title_frame, text="IPC Buffer Overflow Demo",
                 font=("Consolas", 16, "bold"),
                 fg="#cdd6f4", bg="#313244").pack()

        # ── mode selector ────────────────────────────────────────────────
        mode_frame = tk.LabelFrame(self, text=" Server Mode ",
                                   font=("Consolas", 10, "bold"),
                                   fg="#cba6f7", bg="#1e1e2e",
                                   bd=2, relief="groove")
        mode_frame.pack(fill="x", **PAD)

        self._mode_var = tk.StringVar(value="safe")
        tk.Radiobutton(mode_frame, text="Safe Server  (bounds checked)",
                       variable=self._mode_var, value="safe",
                       font=("Consolas", 10), fg="#a6e3a1", bg="#1e1e2e",
                       selectcolor="#313244",
                       command=self._on_mode_change).pack(side="left", padx=12, pady=4)
        tk.Radiobutton(mode_frame, text="Vulnerable Server  (no bounds check)",
                       variable=self._mode_var, value="vulnerable",
                       font=("Consolas", 10), fg="#f38ba8", bg="#1e1e2e",
                       selectcolor="#313244",
                       command=self._on_mode_change).pack(side="left", padx=12, pady=4)

        self._server_status = tk.Label(mode_frame, text="● Server: stopped",
                                       font=("Consolas", 9), fg="#6c7086",
                                       bg="#1e1e2e")
        self._server_status.pack(side="right", padx=12)

        # ── start / stop buttons ─────────────────────────────────────────
        btn_frame = tk.Frame(self, bg="#1e1e2e")
        btn_frame.pack(fill="x", padx=12, pady=(0, 4))
        self._start_btn = tk.Button(btn_frame, text="▶  Start Server",
                                    font=("Consolas", 10, "bold"),
                                    bg="#a6e3a1", fg="#1e1e2e",
                                    activebackground="#94e2a1",
                                    relief="flat", padx=10,
                                    command=self._start_server)
        self._start_btn.pack(side="left", padx=(0, 8))
        self._stop_btn = tk.Button(btn_frame, text="■  Stop Server",
                                   font=("Consolas", 10, "bold"),
                                   bg="#f38ba8", fg="#1e1e2e",
                                   activebackground="#e38ba8",
                                   relief="flat", padx=10, state="disabled",
                                   command=self._stop_server)
        self._stop_btn.pack(side="left")

        # ── input fields ─────────────────────────────────────────────────
        input_frame = tk.LabelFrame(self, text=" Send Message ",
                                    font=("Consolas", 10, "bold"),
                                    fg="#cba6f7", bg="#1e1e2e",
                                    bd=2, relief="groove")
        input_frame.pack(fill="x", **PAD)

        tk.Label(input_frame, text="Command:", font=("Consolas", 10),
                 fg="#cdd6f4", bg="#1e1e2e").grid(row=0, column=0,
                                                   sticky="w", padx=8, pady=4)
        self._cmd_var = tk.StringVar(value="HELLO")
        tk.Entry(input_frame, textvariable=self._cmd_var,
                 font=("Consolas", 10), bg="#313244", fg="#cdd6f4",
                 insertbackground="#cdd6f4", width=18,
                 relief="flat").grid(row=0, column=1, sticky="w", padx=4, pady=4)

        tk.Label(input_frame, text="Payload:", font=("Consolas", 10),
                 fg="#cdd6f4", bg="#1e1e2e").grid(row=1, column=0,
                                                   sticky="w", padx=8, pady=4)
        self._payload_var = tk.StringVar(value="Hello, server!")
        self._payload_entry = tk.Entry(
            input_frame, textvariable=self._payload_var,
            font=("Consolas", 10), bg="#313244",
            fg="#cdd6f4", insertbackground="#cdd6f4",
            width=52, relief="flat",
            validate="key", validatecommand=self._vcmd,
        )
        self._payload_entry.grid(row=1, column=1, sticky="w", padx=4, pady=4)
        self._payload_var.trace_add("write", self._update_buffer_bar)

        # char-limit hint shown next to the field in safe mode
        self._limit_label = tk.Label(input_frame,
                                     text="", font=("Consolas", 9),
                                     fg="#f38ba8", bg="#1e1e2e")
        self._limit_label.grid(row=1, column=2, padx=4)

        tk.Button(input_frame, text="Send  ➤",
                  font=("Consolas", 10, "bold"),
                  bg="#89b4fa", fg="#1e1e2e",
                  activebackground="#79a4ea",
                  relief="flat", padx=10,
                  command=self._send).grid(row=1, column=3, padx=8, pady=4)

        # ── buffer visualizer ─────────────────────────────────────────────
        buf_frame = tk.LabelFrame(self, text=" Buffer Visualizer ",
                                  font=("Consolas", 10, "bold"),
                                  fg="#cba6f7", bg="#1e1e2e",
                                  bd=2, relief="groove")
        buf_frame.pack(fill="x", **PAD)

        # memory address row
        addr_row = tk.Frame(buf_frame, bg="#1e1e2e")
        addr_row.pack(fill="x", padx=8, pady=(6, 0))

        tk.Label(addr_row, text="local_buffer  →",
                 font=("Consolas", 9, "bold"),
                 fg="#6c7086", bg="#1e1e2e").pack(side="left")
        self._addr_label = tk.Label(addr_row,
                                    text="address: (start server to reveal)",
                                    font=("Consolas", 9),
                                    fg="#45475a", bg="#1e1e2e")
        self._addr_label.pack(side="left", padx=6)

        self._size_label = tk.Label(addr_row,
                                    text=f"size: {LOCAL_BUF_SIZE} bytes",
                                    font=("Consolas", 9),
                                    fg="#6c7086", bg="#1e1e2e")
        self._size_label.pack(side="left", padx=10)

        self._buf_canvas = tk.Canvas(buf_frame, height=36, bg="#181825",
                                     highlightthickness=0)
        self._buf_canvas.pack(fill="x", padx=8, pady=4)
        self._buf_label = tk.Label(buf_frame,
                                   text=f"Payload: 0 bytes  |  Buffer limit: {LOCAL_BUF_SIZE} bytes",
                                   font=("Consolas", 9), fg="#6c7086", bg="#1e1e2e")
        self._buf_label.pack(pady=(0, 4))
        self.after(100, self._update_buffer_bar)

        # ── quick-fire overflow button ────────────────────────────────────
        overflow_frame = tk.Frame(self, bg="#1e1e2e")
        overflow_frame.pack(fill="x", padx=12, pady=(0, 4))
        tk.Button(overflow_frame,
                  text="💥  Send Overflow Payload  (48 × 'A')",
                  font=("Consolas", 10, "bold"),
                  bg="#fab387", fg="#1e1e2e",
                  activebackground="#ea9377",
                  relief="flat", padx=10,
                  command=self._send_overflow).pack(side="left")
        tk.Button(overflow_frame,
                  text="✔  Send Normal Payload",
                  font=("Consolas", 10, "bold"),
                  bg="#a6e3a1", fg="#1e1e2e",
                  activebackground="#94d391",
                  relief="flat", padx=10,
                  command=self._send_normal).pack(side="left", padx=8)

        # ── output console ────────────────────────────────────────────────
        console_frame = tk.LabelFrame(self, text=" Output ",
                                      font=("Consolas", 10, "bold"),
                                      fg="#cba6f7", bg="#1e1e2e",
                                      bd=2, relief="groove")
        console_frame.pack(fill="both", expand=True, **PAD)

        self._console = scrolledtext.ScrolledText(
            console_frame, font=("Consolas", 10),
            bg="#181825", fg="#cdd6f4",
            insertbackground="#cdd6f4",
            height=14, relief="flat", state="disabled",
        )
        self._console.pack(fill="both", expand=True, padx=6, pady=6)
        self._console.tag_config("ok",      foreground="#a6e3a1")
        self._console.tag_config("error",   foreground="#f38ba8")
        self._console.tag_config("crash",   foreground="#f38ba8",
                                 font=("Consolas", 10, "bold"))
        self._console.tag_config("warn",    foreground="#fab387")
        self._console.tag_config("info",    foreground="#89b4fa")
        self._console.tag_config("heading", foreground="#cba6f7",
                                 font=("Consolas", 10, "bold"))
        self._console.tag_config("overflow", foreground="#f38ba8",
                                 font=("Consolas", 10, "bold"))

        self._log("IPC Buffer Overflow Demo ready.", "heading")
        self._log(f"Safe server buffer: {LOCAL_BUF_SIZE} bytes  |  "
                  f"Payloads > {LOCAL_BUF_SIZE - 1} chars will overflow the vulnerable server.", "info")

    # ── payload validation ───────────────────────────────────────────────

    def _validate_payload_len(self, new_value: str) -> bool:
        """Block input beyond 32 bytes when safe mode is selected."""
        if self._mode_var.get() == "safe":
            return len(new_value.encode()) <= LOCAL_BUF_SIZE
        return True

    # ── buffer address polling ───────────────────────────────────────────

    def _poll_buffer_address(self):
        """Check every 300 ms whether the server has printed its address yet."""
        addr = server_mgr.buffer_address
        if addr:
            mode_tag = "safe-server" if server_mgr.mode == "safe" else "vuln-server"
            self._addr_label.config(
                text=f"address: {addr}",
                fg="#cba6f7"
            )
            self._size_label.config(
                text=f"size: {LOCAL_BUF_SIZE} bytes  [{mode_tag}]",
                fg="#89b4fa"
            )
        elif not server_mgr.is_running():
            self._addr_label.config(
                text="address: (start server to reveal)",
                fg="#45475a"
            )
            self._size_label.config(
                text=f"size: {LOCAL_BUF_SIZE} bytes",
                fg="#6c7086"
            )
        self.after(300, self._poll_buffer_address)

    # ── buffer bar ──────────────────────────────────────────────────────

    def _update_buffer_bar(self, *_):
        payload_len = len(self._payload_var.get().encode())
        canvas_w    = self._buf_canvas.winfo_width() or 400
        canvas_h    = 36
        self._buf_canvas.delete("all")

        self._buf_canvas.create_rectangle(4, 8, canvas_w - 4, canvas_h - 8,
                                           fill="#313244", outline="#45475a")

        overflow   = payload_len >= LOCAL_BUF_SIZE
        fill_color = ("#f38ba8" if overflow else
                      "#fab387" if payload_len >= LOCAL_BUF_SIZE * 0.75 else
                      "#a6e3a1")
        fill_w = max(0, min(canvas_w - 8,
                            int((canvas_w - 8) * payload_len / max(PAYLOAD_SIZE, 1))))
        if fill_w > 0:
            self._buf_canvas.create_rectangle(4, 8, 4 + fill_w, canvas_h - 8,
                                               fill=fill_color, outline="")

        marker_x = 4 + int((canvas_w - 8) * LOCAL_BUF_SIZE / PAYLOAD_SIZE)
        self._buf_canvas.create_line(marker_x, 4, marker_x, canvas_h - 4,
                                      fill="#f5c2e7", width=2, dash=(4, 3))
        self._buf_canvas.create_text(marker_x + 3, 6,
                                      text=f"{LOCAL_BUF_SIZE}B limit",
                                      anchor="nw", fill="#f5c2e7",
                                      font=("Consolas", 8))

        label = f"Payload: {payload_len} bytes  |  Buffer limit: {LOCAL_BUF_SIZE} bytes"
        if overflow:
            label += f"  ⚠  OVERFLOW by {payload_len - LOCAL_BUF_SIZE} byte(s)!"
        self._buf_label.config(
            text=label,
            fg="#f38ba8" if overflow else "#6c7086"
        )

        # update safe-mode character limit hint
        if self._mode_var.get() == "safe":
            remaining = LOCAL_BUF_SIZE - payload_len
            if remaining <= 5:
                self._limit_label.config(
                    text=f"{remaining} chars left  [safe cap]",
                    fg="#fab387" if remaining > 0 else "#f38ba8"
                )
            else:
                self._limit_label.config(text="")
        else:
            self._limit_label.config(text="")

    # ── server controls ─────────────────────────────────────────────────

    def _on_mode_change(self):
        if server_mgr.is_running():
            self._stop_server()
        # Enforce 32-char cap if switching to safe and current text is longer
        if self._mode_var.get() == "safe":
            current = self._payload_var.get()
            if len(current.encode()) > LOCAL_BUF_SIZE:
                self._payload_var.set(current.encode()[:LOCAL_BUF_SIZE].decode(errors="ignore"))
        self._update_buffer_bar()

    def _start_server(self):
        mode   = self._mode_var.get()
        result = server_mgr.start(mode)
        self._log(result, "ok" if server_mgr.is_running() else "error")
        self._refresh_server_status()

    def _stop_server(self):
        server_mgr.stop()
        self._log("[server] Stopped.", "warn")
        self._refresh_server_status()

    def _refresh_server_status(self):
        if server_mgr.is_running():
            color = "#f38ba8" if server_mgr.mode == "vulnerable" else "#a6e3a1"
            self._server_status.config(
                text=f"● Server: running ({server_mgr.mode})", fg=color)
            self._start_btn.config(state="disabled")
            self._stop_btn.config(state="normal")
        else:
            self._server_status.config(text="● Server: stopped", fg="#6c7086")
            self._start_btn.config(state="normal")
            self._stop_btn.config(state="disabled")

    # ── sending ─────────────────────────────────────────────────────────

    def _send(self):
        cmd     = self._cmd_var.get().strip() or "MSG"
        payload = self._payload_var.get()
        self._do_send(cmd, payload)

    def _send_overflow(self):
        self._payload_var.set("A" * 48)
        self._do_send("FLOOD", "A" * 48)

    def _send_normal(self):
        self._payload_var.set("Hello, server!")
        self._do_send("HELLO", "Hello, server!")

    def _do_send(self, cmd: str, payload: str):
        if not server_mgr.is_running():
            self._log("No server running — start one first.", "warn")
            return
        socket_path  = VULN_SOCKET_PATH if server_mgr.mode == "vulnerable" else SAFE_SOCKET_PATH
        plen         = len(payload.encode())
        is_overflow  = plen >= LOCAL_BUF_SIZE
        is_vuln_mode = server_mgr.mode == "vulnerable"

        self._log(f"\n─── Sending ──────────────────────────", "info")
        self._log(f"  Command : {cmd}", "info")
        self._log(f"  Payload : {payload!r}  ({plen} bytes)", "info")

        if is_overflow and is_vuln_mode:
            self._log(f"  Buffer  : {LOCAL_BUF_SIZE} bytes  |  ⚠  OVERFLOW EXPECTED "
                      f"({plen - LOCAL_BUF_SIZE} bytes past boundary)", "overflow")
        elif is_overflow and not is_vuln_mode:
            self._log(f"  Buffer  : {LOCAL_BUF_SIZE} bytes  |  safe server will reject this", "warn")
        else:
            self._log(f"  Buffer  : {LOCAL_BUF_SIZE} bytes  |  within bounds", "info")

        def _worker():
            response = send_message(socket_path, cmd, payload)
            crashed  = response.startswith("ERROR: Connection refused") or \
                       response.startswith("ERROR: Timed out")

            if is_overflow and is_vuln_mode:
                if crashed:
                    self._log(f"  Response: {response}", "error")
                    self._log("", "")
                    self._log("  💥 SERVER CRASHED", "crash")
                    self._log("     Stack overflow corrupted the return address.", "crash")
                    self._log("     The process received SIGSEGV (Segmentation Fault).", "error")
                    self._log("     Restart the server to continue.", "warn")
                    self.after(0, self._refresh_server_status)
                else:
                    self._log(f"  Response: {response}", "warn")
                    self._log("", "")
                    self._log("  ⚠  BUFFER OVERFLOW OCCURRED", "overflow")
                    self._log(f"     {plen} bytes written into a {LOCAL_BUF_SIZE}-byte buffer.", "error")
                    self._log(f"     {plen - LOCAL_BUF_SIZE} bytes spilled into adjacent stack memory.", "error")
                    self._log("     Return address and saved frame pointer may be corrupted.", "error")
                    self._log("     Server is unstable — it may crash on the next request.", "warn")
            else:
                tag = "error" if response.startswith("ERROR") else "ok"
                self._log(f"  Response: {response}", tag)

        threading.Thread(target=_worker, daemon=True).start()

    # ── console helper ──────────────────────────────────────────────────

    def _log(self, text: str, tag: str = ""):
        self._console.config(state="normal")
        self._console.insert("end", text + "\n", tag)
        self._console.see("end")
        self._console.config(state="disabled")

    # ── cleanup ─────────────────────────────────────────────────────────

    def _on_close(self):
        server_mgr.stop()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()
