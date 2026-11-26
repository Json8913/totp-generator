#!/usr/bin/env python3
"""Offline desktop authenticator for locally entered test secrets."""

import time
import tkinter as tk
from tkinter import ttk

from totp import generate_secret, totp


BG = "#0b1220"
PANEL = "#121d2e"
TEXT = "#edf4ff"
MUTED = "#9bacbf"
ACCENT = "#45d6c5"


class TotpApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Offline TOTP Authenticator")
        self.geometry("700x540")
        self.minsize(560, 460)
        self.configure(bg=BG)
        self.secret = tk.StringVar()
        self.reveal = tk.BooleanVar(value=False)
        self._style()
        self._build()
        self.after(200, self.refresh)
        self.protocol("WM_DELETE_WINDOW", self.close)

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", font=("Arial", 10))
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("Card.TLabel", background=PANEL, foreground=TEXT)
        style.configure("TEntry", fieldbackground="#0f1928", foreground=TEXT,
                        insertcolor=TEXT, bordercolor="#31445b")
        style.configure("TButton", padding=(12, 8), background="#24364b",
                        foreground=TEXT, borderwidth=0)
        style.configure("Accent.TButton", background=ACCENT, foreground="#07131b",
                        font=("Arial", 10, "bold"))

    def _build(self):
        shell = ttk.Frame(self, padding=24)
        shell.pack(fill="both", expand=True)
        ttk.Label(shell, text="LOCAL AUTHENTICATOR  /  NO NETWORK", style="Muted.TLabel").pack(anchor="w")
        ttk.Label(shell, text="Time-based one-time codes", font=("Arial", 24, "bold")).pack(anchor="w", pady=(6, 4))
        ttk.Label(shell, text="Enter a test secret or create a new one. Nothing is saved to disk.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 18))
        card = ttk.Frame(shell, style="Card.TFrame", padding=18)
        card.pack(fill="x")
        ttk.Label(card, text="Base32 secret", style="Card.TLabel").pack(anchor="w", pady=(0, 7))
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x")
        self.entry = ttk.Entry(row, textvariable=self.secret, show="•")
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ttk.Button(row, text="New test secret", command=self.new_secret).pack(side="left")
        ttk.Checkbutton(card, text="Show secret", variable=self.reveal, command=self.toggle).pack(anchor="w", pady=(8, 0))
        code_card = ttk.Frame(shell, style="Card.TFrame", padding=22)
        code_card.pack(fill="x", pady=(16, 0))
        ttk.Label(code_card, text="CURRENT CODE", style="Card.TLabel").pack(anchor="w")
        self.code = ttk.Label(code_card, text="••••••", style="Card.TLabel",
                              font=("Arial", 34, "bold"))
        self.code.pack(anchor="w", pady=(5, 0))
        self.progress = ttk.Label(code_card, text="Enter a valid secret to begin.", style="Card.TLabel")
        self.progress.pack(anchor="w", pady=(4, 0))
        self.status = tk.StringVar(value="Codes refresh every 30 seconds. Use test accounts only.")
        ttk.Label(shell, textvariable=self.status, style="Muted.TLabel", wraplength=620).pack(anchor="w", pady=(16, 0))
        ttk.Label(shell, text="Keep the secret private. Anyone with it can generate your codes.",
                  style="Muted.TLabel").pack(anchor="w", pady=(10, 0))

    def toggle(self):
        self.entry.configure(show="" if self.reveal.get() else "•")

    def new_secret(self):
        self.secret.set(generate_secret())
        self.reveal.set(True)
        self.toggle()
        self.status.set("New secret created in memory. Save it securely before closing if you need it.")

    def refresh(self):
        value = self.secret.get().strip()
        try:
            now = time.time()
            self.code.configure(text=totp(value, now))
            self.progress.configure(text=f"Refresh in {30 - int(now) % 30} seconds")
        except (ValueError, OSError):
            self.code.configure(text="••••••")
            self.progress.configure(text="Enter a valid Base32 secret.")
        self.after(500, self.refresh)

    def close(self):
        self.secret.set("")
        self.destroy()


if __name__ == "__main__":
    TotpApp().mainloop()
