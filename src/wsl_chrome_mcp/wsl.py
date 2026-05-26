"""WSL detection and Windows integration utilities."""

from __future__ import annotations

import os
import subprocess
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def is_wsl() -> bool:
    """Detect if running inside WSL (Windows Subsystem for Linux)."""
    # Check for WSL-specific indicators
    if os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
        return True

    # Check /proc/version for Microsoft/WSL indicators
    try:
        with open("/proc/version") as f:
            version = f.read().lower()
            if "microsoft" in version or "wsl" in version:
                return True
    except (FileNotFoundError, PermissionError):
        pass

    # Check WSL_DISTRO_NAME environment variable
    return bool(os.environ.get("WSL_DISTRO_NAME"))


@lru_cache(maxsize=1)
def is_mirrored_networking() -> bool:
    """Detect WSL2 mirrored networking mode.

    When networkingMode=mirrored is set in .wslconfig, WSL2 shares the Windows
    network stack and localhost points directly to Windows services.
    """
    if not is_wsl():
        return False

    for user_dir in Path("/mnt/c/Users").iterdir():
        if not user_dir.is_dir() or user_dir.name in (
            "Public",
            "Default",
            "Default User",
            "All Users",
        ):
            continue
        wslconfig = user_dir / ".wslconfig"
        if not wslconfig.exists():
            continue
        try:
            text = wslconfig.read_text(encoding="utf-8", errors="replace").lower()
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "networkingmode" in stripped and "mirrored" in stripped:
                    return True
        except OSError:
            continue

    return False


@lru_cache(maxsize=1)
def get_windows_host_ip() -> str:
    """Get the IP address of the Windows host from WSL.

    Returns the IP that WSL can use to reach Windows services.
    """
    if not is_wsl():
        return "127.0.0.1"

    # Method 1: Use /etc/resolv.conf nameserver (most reliable for WSL2)
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.strip().startswith("nameserver"):
                    ip = line.split()[1]
                    # Validate it's not a local address
                    if not ip.startswith("127."):
                        return ip
    except (FileNotFoundError, PermissionError, IndexError):
        pass

    # Method 2: Use WSL_HOST_IP if available (newer WSL versions)
    host_ip = os.environ.get("WSL_HOST_IP")
    if host_ip:
        return host_ip

    # Method 3: Parse ip route for Windows gateway
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            # Output like: "default via 172.x.x.1 dev eth0"
            parts = result.stdout.strip().split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Method 4: Ask Windows directly via PowerShell for the WSL adapter IP
    try:
        ps_cmd = (
            "(Get-NetIPAddress -InterfaceAlias 'vEthernet (WSL*)' "
            "-AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress"
        )
        # Find powershell by scanning /mnt drives
        powershell = None
        mnt_path = Path("/mnt")
        if mnt_path.exists():
            for drive in mnt_path.iterdir():
                if drive.is_dir() and len(drive.name) == 1:
                    ps_path = drive / "Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
                    if ps_path.exists():
                        powershell = str(ps_path)
                        break
        if powershell:
            result = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().split()[0]
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError, OSError):
        pass

    # Fallback to localhost (works for some WSL1 configurations)
    return "127.0.0.1"


@lru_cache(maxsize=1)
def _find_windows_executable(name: str) -> str | None:
    """Dynamically find a Windows executable from WSL.

    Tries multiple methods to locate the executable without hardcoding paths.

    Args:
        name: Name of the executable (e.g., "powershell.exe", "cmd.exe")

    Returns:
        Full path to the executable, or just the name if found in PATH.
    """
    # Method 1: Check if it's directly accessible via WSL interop PATH
    try:
        result = subprocess.run(
            ["which", name],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Method 2: Use wslvar to get SYSTEMROOT and construct path dynamically
    try:
        result = subprocess.run(
            ["wslvar", "SYSTEMROOT"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            systemroot = result.stdout.strip()
            # Convert to WSL path and look for the executable
            wsl_systemroot = convert_windows_to_wsl_path(systemroot)

            # Common locations relative to SYSTEMROOT
            search_paths = [
                f"{wsl_systemroot}/System32/WindowsPowerShell/v1.0/{name}",
                f"{wsl_systemroot}/System32/{name}",
                f"{wsl_systemroot}/SysWOW64/WindowsPowerShell/v1.0/{name}",
            ]
            for path in search_paths:
                if os.path.exists(path):
                    return path
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Method 3: Check common mount points without hardcoding drive letters
    try:
        # List available Windows mounts
        mnt_path = Path("/mnt")
        if mnt_path.exists():
            for drive in mnt_path.iterdir():
                if drive.is_dir() and len(drive.name) == 1:
                    # Check Windows/System32 on each mounted drive
                    ps_path = drive / "Windows/System32/WindowsPowerShell/v1.0" / name
                    if ps_path.exists():
                        return str(ps_path)
                    cmd_path = drive / "Windows/System32" / name
                    if cmd_path.exists():
                        return str(cmd_path)
    except (PermissionError, OSError):
        pass

    return None


def run_windows_command(command: str, *, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    """Execute a command on Windows from WSL using powershell.exe.

    Args:
        command: The PowerShell command to execute on Windows.
        timeout: Command timeout in seconds.

    Returns:
        CompletedProcess with stdout and stderr.

    Raises:
        RuntimeError: If not in WSL or PowerShell cannot be found.
    """
    if not is_wsl():
        raise RuntimeError("run_windows_command can only be used in WSL")

    # Dynamically find PowerShell
    powershell = _find_windows_executable("powershell.exe")
    if not powershell:
        raise RuntimeError(
            "Could not find powershell.exe. Ensure WSL interop is enabled "
            "or Windows is properly mounted."
        )

    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        timeout=timeout,
    )
    # Decode with error handling for non-UTF-8 output
    stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""
    stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
    return subprocess.CompletedProcess(result.args, result.returncode, stdout, stderr)


def get_windows_chrome_paths() -> list[str]:
    """Get possible Chrome/Edge installation paths on Windows."""
    return [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
        r"$env:PROGRAMFILES\Google\Chrome\Application\chrome.exe",
        r"$env:PROGRAMFILES(X86)\Google\Chrome\Application\chrome.exe",
    ]


def find_windows_chrome() -> str | None:
    """Find Chrome or Edge executable on Windows from WSL.

    Returns:
        The path to chrome.exe/msedge.exe if found, None otherwise.
    """
    if not is_wsl():
        return None

    # PowerShell script to find Chrome or Edge
    ps_script = """
    $paths = @(
        "${env:PROGRAMFILES(x86)}\\Microsoft\\Edge\\Application\\msedge.exe",
        "$env:PROGRAMFILES\\Microsoft\\Edge\\Application\\msedge.exe",
        "$env:PROGRAMFILES\\Google\\Chrome\\Application\\chrome.exe",
        "${env:PROGRAMFILES(x86)}\\Google\\Chrome\\Application\\chrome.exe",
        "$env:LOCALAPPDATA\\Google\\Chrome\\Application\\chrome.exe"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Write-Output $path
            exit 0
        }
    }
    exit 1
    """

    try:
        result = run_windows_command(ps_script, timeout=10.0)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, RuntimeError):
        pass

    return None


def convert_wsl_to_windows_path(wsl_path: str | Path) -> str:
    """Convert a WSL path to a Windows path.

    Args:
        wsl_path: Path in WSL format (e.g., /mnt/c/Users/...)

    Returns:
        Windows path (e.g., C:\\Users\\...)
    """
    try:
        result = subprocess.run(
            ["wslpath", "-w", str(wsl_path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: manual conversion for /mnt/X/ paths
    path_str = str(wsl_path)
    if path_str.startswith("/mnt/") and len(path_str) > 5:
        drive = path_str[5].upper()
        rest = path_str[6:].replace("/", "\\")
        return f"{drive}:{rest}"

    return path_str


def convert_windows_to_wsl_path(windows_path: str) -> str:
    """Convert a Windows path to a WSL path.

    Args:
        windows_path: Path in Windows format (e.g., C:\\Users\\...)

    Returns:
        WSL path (e.g., /mnt/c/Users/...)
    """
    try:
        result = subprocess.run(
            ["wslpath", "-u", windows_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: manual conversion
    if len(windows_path) >= 2 and windows_path[1] == ":":
        drive = windows_path[0].lower()
        rest = windows_path[2:].replace("\\", "/")
        return f"/mnt/{drive}{rest}"

    return windows_path
