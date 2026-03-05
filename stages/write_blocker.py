"""Write Blocker — mounts USB read-only before any scanning begins."""
from __future__ import annotations
import subprocess
import sys
import tempfile
import os
from pathlib import Path
from core.pipeline import PipelineContext, PipelineStage
from core.orchestrator import AbortPipeline


class WriteBlocker(PipelineStage):
    def __init__(self):
        super().__init__("Write Blocker")

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if sys.platform.startswith("linux"):
            return self._linux_block(ctx)
        elif sys.platform == "win32":
            return self._windows_block(ctx)
        else:
            raise AbortPipeline(f"Unsupported platform: {sys.platform}")

    def _linux_block(self, ctx: PipelineContext) -> PipelineContext:
        mount_point = tempfile.mkdtemp(prefix="semper_usb_")
        result = subprocess.run(
            ["mount", "-o", "ro", ctx.usb_path, mount_point],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise AbortPipeline(
                f"Write-block failed: could not mount {ctx.usb_path} read-only. "
                f"stderr: {result.stderr}. ABORTING — do not proceed without forensic integrity."
            )
        ctx.mount_point = mount_point
        return ctx

    def _windows_block(self, ctx: PipelineContext) -> PipelineContext:
        """
        Set WriteProtect registry key for USB storage, then use the drive letter directly.
        Requires admin privileges.
        """
        try:
            import winreg
            key_path = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception as e:
            raise AbortPipeline(
                f"Write-block failed on Windows: {e}. "
                "Run Semper USB as Administrator."
            )
        ctx.mount_point = ctx.usb_path   # On Windows, use drive letter directly
        return ctx
