"""Scan progress overlay — persistent window shown during pipeline execution."""
from __future__ import annotations
import queue
import threading
import tkinter as tk
from tkinter import ttk
import subprocess, sys
from datetime import datetime

STAGES = ["Write Blocker", "Scanner", "Triage", "Copier", "Sorter", "Packager"]


class ScanOverlay:
    def __init__(self, usb_label: str):
        self._q: queue.Queue = queue.Queue()
        self._label = usb_label
        self._start = datetime.now()
        self._root: tk.Tk | None = None

    def build(self):
        root = tk.Tk()
        self._root = root
        root.title("Semper USB")
        root.resizable(False, False)

        tk.Label(root, text=f"Scanning {self._label}", font=("Helvetica", 13, "bold")).pack(pady=(12, 4))
        ttk.Separator(root).pack(fill="x", padx=8)

        self._stage_label = tk.Label(root, text="Initializing...", anchor="w")
        self._stage_label.pack(padx=16, pady=(8, 0), fill="x")

        self._progress = ttk.Progressbar(root, length=340, mode="determinate")
        self._progress.pack(padx=16, pady=4)

        self._pct_label = tk.Label(root, text="0%", anchor="e")
        self._pct_label.pack(padx=16, fill="x")

        ttk.Separator(root).pack(fill="x", padx=8, pady=4)

        self._crumb_vars = {}
        for stage in STAGES:
            var = tk.StringVar(value=f"  {stage}")
            self._crumb_vars[stage] = var
            tk.Label(root, textvariable=var, anchor="w").pack(padx=24, fill="x")

        ttk.Separator(root).pack(fill="x", padx=8, pady=4)
        self._elapsed_label = tk.Label(root, text="Elapsed: 00:00:00", anchor="w")
        self._elapsed_label.pack(padx=16, pady=(0, 12), fill="x")

        root.after(100, self._poll)
        root.after(1000, self._tick)
        root.mainloop()

    def _tick(self):
        elapsed = datetime.now() - self._start
        secs = int(elapsed.total_seconds())
        h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
        self._elapsed_label.config(text=f"Elapsed: {h:02d}:{m:02d}:{s:02d}")
        if self._root:
            self._root.after(1000, self._tick)

    def _poll(self):
        try:
            while True:
                event = self._q.get_nowait()
                self._handle(event)
        except queue.Empty:
            pass
        if self._root:
            self._root.after(100, self._poll)

    def _handle(self, event: dict):
        kind = event.get("type")
        if kind == "stage_start":
            stage = event["stage"]
            self._stage_label.config(text=f"Stage: {stage}...")
            for s, var in self._crumb_vars.items():
                if s == stage:
                    var.set(f"  > {s}")
        elif kind == "stage_done":
            stage = event["stage"]
            self._crumb_vars[stage].set(f"  [done] {stage}")
        elif kind == "progress":
            pct = event.get("pct", 0)
            self._progress["value"] = pct
            self._pct_label.config(text=f"{pct:.0f}%  ({event.get('current',0)}/{event.get('total',0)})")
        elif kind == "complete":
            self._show_summary(event)
        elif kind == "aborted":
            self._show_abort(event)

    def _show_summary(self, event: dict):
        if not self._root:
            return
        for widget in self._root.winfo_children():
            widget.destroy()
        tk.Label(self._root, text="Scan Complete", font=("Helvetica", 14, "bold")).pack(pady=(16, 4))
        tk.Label(self._root, text=f"{event.get('total_files', 0)} files scanned   |   {event.get('flagged', 0)} threats found").pack()
        for cat, count in event.get("categories", {}).items():
            tk.Label(self._root, text=f"  {cat}: {count}", anchor="w").pack(padx=24, fill="x")
        tk.Label(self._root, text=f"\nOutput:\n{event.get('output_dir','')}", justify="left").pack(padx=16)
        btn = tk.Frame(self._root)
        btn.pack(pady=12)
        output_dir = event.get("output_dir", "")
        tk.Button(btn, text="Open Output Folder", command=lambda: self._open_folder(output_dir)).pack(side="left", padx=8)
        tk.Button(btn, text="Dismiss", command=self._root.destroy).pack(side="left", padx=8)

    def _show_abort(self, event: dict):
        if not self._root:
            return
        for widget in self._root.winfo_children():
            widget.destroy()
        tk.Label(self._root, text="SCAN ABORTED", font=("Helvetica", 14, "bold"), fg="red").pack(pady=16)
        tk.Label(self._root, text=event.get("reason", "Unknown error"), wraplength=320).pack(padx=16)
        tk.Button(self._root, text="Dismiss", command=self._root.destroy).pack(pady=12)

    def _open_folder(self, path: str):
        if sys.platform == "win32":
            subprocess.Popen(["explorer", path])
        else:
            subprocess.Popen(["xdg-open", path])

    def push(self, event: dict):
        """Thread-safe — call from pipeline thread."""
        self._q.put(event)

    def run_in_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.build, daemon=True)
        t.start()
        return t
