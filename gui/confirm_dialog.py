"""Confirm dialog — shown when USB insertion detected."""
from __future__ import annotations
import tkinter as tk
from tkinter import ttk


class ConfirmDialog:
    def __init__(self, usb_label: str, usb_serial: str, usb_path: str):
        self.result = False
        self._root = tk.Tk()
        self._root.title("Semper USB — Device Detected")
        self._root.resizable(False, False)
        self._build(usb_label, usb_serial, usb_path)

    def _build(self, label, serial, path):
        root = self._root
        tk.Label(root, text="USB Device Detected", font=("Helvetica", 14, "bold")).pack(pady=(16, 4))
        frame = tk.Frame(root)
        frame.pack(padx=24, pady=8)
        row = 0
        for key, val in [("Label", label), ("Serial", serial), ("Path", path)]:
            tk.Label(frame, text=f"{key}:", anchor="w", width=8).grid(row=row, column=0, sticky="w")
            tk.Label(frame, text=val, anchor="w").grid(row=row, column=1, sticky="w")
            row += 1
        tk.Label(root, text="Semper USB will mount this drive read-only\nand scan for malicious content.",
                 justify="center").pack(pady=8)
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=(4, 16))
        tk.Button(btn_frame, text="Scan Now", width=12, command=self._scan).pack(side="left", padx=8)
        tk.Button(btn_frame, text="Ignore",   width=12, command=self._ignore).pack(side="left", padx=8)

    def _scan(self):
        self.result = True
        self._root.destroy()

    def _ignore(self):
        self.result = False
        self._root.destroy()

    def show(self) -> bool:
        self._root.mainloop()
        return self.result
