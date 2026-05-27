"""Chrome pool manager with per-session Chrome instances (isolated mode)
or shared Chrome with per-session BrowserContexts (profile mode).

Isolated mode: each session gets its own Chrome process on a unique port,
providing complete isolation between sessions.

Profile mode: all sessions share a single Chrome process and debugging port.
Session isolation is provided by one CDP BrowserContext per session.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .cdp_proxy import CDPProxyClient
from .persistent_cdp import PersistentCDPClient, enable_domains
from .ps_relay import PowerShellCDPRelay
from .session_store import SessionRecord, SessionStore
from .wsl import get_windows_host_ip, is_mirrored_networking, is_wsl, run_windows_command

logger = logging.getLogger(__name__)


@dataclass
class ConsoleMessage:
    """A console message captured from the browser."""

    type: str  # log, warn, error, info, debug
    text: str
    timestamp: float | None = None
    stack_trace: list[dict[str, Any]] | None = None
    args: list[Any] | None = None


@dataclass
class NetworkRequest:
    """A network request captured from the browser."""

    request_id: str
    url: str
    method: str
    timestamp: float | None = None
    type: str | None = None  # Document, XHR, Fetch, etc.
    headers: dict[str, str] = field(default_factory=dict)
    post_data: str | None = None
    response: dict[str, Any] | None = None
    response_body: bytes | None = None


@dataclass
class DialogInfo:
    """Information about a pending browser dialog."""

    type: str  # alert, confirm, prompt, beforeunload
    message: str
    default_prompt: str | None = None
    url: str | None = None


@dataclass
class ChromeInstance:
    """Session state backed by a Chrome process.

    In isolated mode, each instance owns its own Chrome process.
    In profile mode, instances share a single Chrome process.
    Maintains persistent page-level CDP connection for real-time events.
    """

    session_id: str
    port: int
    pid: int | None
    user_data_dir: str
    created_at: datetime = field(default_factory=datetime.now)

    # Connection components
    cdp: PersistentCDPClient | PowerShellCDPRelay | None = None  # For current page
    proxy: CDPProxyClient | None = None  # Fallback for one-shot commands
    browser_context_id: str | None = None

    # Tab tracking within this Chrome instance
    current_target_id: str | None = None
    targets: list[str] = field(default_factory=list)
    window_id: int | None = None

    # Event-collected data
    console_messages: list[ConsoleMessage] = field(default_factory=list)
    network_requests: dict[str, NetworkRequest] = field(default_factory=dict)
    pending_dialog: DialogInfo | None = None

    # Snapshot cache for accessibility tree
    snapshot_cache: dict[str, dict[str, Any]] = field(default_factory=dict)
    snapshot_node_ids: dict[str, int] = field(default_factory=dict)  # uid -> backendNodeId

    # Performance trace state
    trace_active: bool = False
    trace_events: list[dict[str, Any]] = field(default_factory=list)

    # Emulation state (persisted across navigations)
    emulation_state: dict[str, Any] = field(default_factory=dict)

    # Per-instance Chrome management (isolated mode)
    instance_browser_cdp: PersistentCDPClient | None = None
    owns_chrome: bool = False

    @property
    def is_connected(self) -> bool:
        """Check if CDP client is connected."""
        return self.cdp is not None and self.cdp.is_connected

    def clear_page_state(self) -> None:
        """Clear state that should be reset on navigation."""
        self.console_messages.clear()
        self.network_requests.clear()
        self.snapshot_cache.clear()
        self.snapshot_node_ids.clear()

    def add_console_message(
        self,
        msg_type: str,
        text: str,
        timestamp: float | None = None,
        stack_trace: list[dict[str, Any]] | None = None,
        args: list[Any] | None = None,
    ) -> None:
        """Add a console message to the collection."""
        self.console_messages.append(
            ConsoleMessage(
                type=msg_type,
                text=text,
                timestamp=timestamp,
                stack_trace=stack_trace,
                args=args,
            )
        )

    def add_network_request(self, request_id: str, request: NetworkRequest) -> None:
        """Add or update a network request."""
        self.network_requests[request_id] = request

    def set_dialog(self, dialog: DialogInfo | None) -> None:
        """Set or clear the pending dialog."""
        self.pending_dialog = dialog


class ChromePoolManager:
    """Manages Chrome instances for MCP sessions.

    Isolated mode: one Chrome process per session (complete isolation).
    Profile mode: shared Chrome with per-session BrowserContexts.
    """

    def __init__(
        self,
        port_min: int = 9222,
        port_max: int = 9322,
        headless: bool = False,
        profile_mode: str = "isolated",
        profile_name: str = "",
    ) -> None:
        self._instances: dict[str, ChromeInstance] = {}
        self._port = port_min
        self._port_max = port_max
        self._headless = headless
        self._profile_mode = profile_mode
        self._profile_name = profile_name
        self._chrome_path: str | None = None
        self._direct_tcp_works: bool = True

        # Per-session port tracking (isolated mode)
        self._used_ports: set[int] = set()

        # Shared Chrome state (profile mode only)
        self._shared_pid: int | None = None
        self._shared_user_data_dir: str | None = None
        self._shared_proxy: CDPProxyClient | None = None
        self._browser_cdp: PersistentCDPClient | None = None
        self._default_tabs_closed: bool = False
        self._profile_context_id: str | None = None

        self._cleanup_orphaned_temp_dirs()
        self._session_store = SessionStore()
        self._session_store.cleanup_stale()

        # Pre-populate used ports from surviving session records
        # to prevent port collision with orphan Chrome instances
        for record in self._session_store.list_all():
            self._used_ports.add(record.port)

    def _cleanup_orphaned_temp_dirs(self) -> None:
        """Remove orphaned chrome-mcp-* temp directories from previous crashes.

        Only removes directories older than 24 hours to avoid deleting
        active session data.
        """
        ps_cmd = (
            "Get-ChildItem -Path $env:TEMP -Filter 'chrome-mcp-*' "
            "-Directory -ErrorAction SilentlyContinue | "
            "Where-Object { $_.CreationTime -lt (Get-Date).AddHours(-24) } | "
            "ForEach-Object { "
            "Remove-Item -Path $_.FullName -Recurse -Force "
            "-ErrorAction SilentlyContinue; "
            "Write-Output $_.Name "
            "}"
        )
        try:
            result = run_windows_command(ps_cmd, timeout=30.0)
            if result.returncode == 0 and result.stdout.strip():
                removed = [d for d in result.stdout.strip().split("\n") if d.strip()]
                if removed:
                    logger.info(
                        "Cleaned up %d orphaned temp dir(s): %s",
                        len(removed),
                        ", ".join(removed),
                    )
        except Exception as e:
            logger.warning("Failed to clean up orphaned temp dirs: %s", e)

    async def _try_reconnect_from_record(self, record: SessionRecord) -> ChromeInstance | None:
        """Try to reconnect to an orphaned Chrome using persisted session data."""
        try:
            proxy = CDPProxyClient(record.port)
            version = await proxy.get_version()
            if not version:
                return None
            logger.info(
                "Found orphaned Chrome on port %d for session %s", record.port, record.session_id
            )
            targets = await proxy.list_targets()
            page_targets = [t for t in targets if t.get("type") == "page"]
            if not page_targets:
                return None
            current_target_id = record.current_target_id
            target_exists = any(t.get("id") == current_target_id for t in page_targets)
            if not target_exists:
                current_target_id = page_targets[0].get("id")
            all_target_ids = [str(t["id"]) for t in page_targets if t.get("id")]
            instance = ChromeInstance(
                session_id=record.session_id,
                port=record.port,
                pid=record.pid,
                user_data_dir="",
                proxy=proxy,
                browser_context_id=record.browser_context_id,
                current_target_id=current_target_id,
                targets=all_target_ids,
                owns_chrome=(record.profile_mode != "profile"),
            )
            if record.profile_mode != "profile":
                self._used_ports.add(record.port)
            try:
                if instance.owns_chrome:
                    await self._connect_instance_browser_cdp(instance)
                if current_target_id:
                    await self._connect_cdp(instance, current_target_id)
            except Exception as e:
                logger.warning("Reconnection CDP setup failed (proxy fallback): %s", e)
            logger.info(
                "Reconnected to orphaned Chrome session %s on port %d",
                record.session_id,
                record.port,
            )
            return instance
        except Exception as e:
            logger.debug("Failed to reconnect session %s: %s", record.session_id, e)
            return None

    # --- Port allocation (isolated mode) ---

    def _is_port_in_use(self, port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except (ConnectionRefusedError, TimeoutError, OSError):
            return False

    def _allocate_port(self) -> int:
        """Find next available port in range.

        Returns:
            An available port number.

        Raises:
            RuntimeError: If no ports are available.
        """
        for port in range(self._port, self._port_max):
            if port in self._used_ports:
                continue
            if self._is_port_in_use(port):
                logger.debug("Port %d in use (OS probe), skipping", port)
                self._used_ports.add(port)
                continue
            self._used_ports.add(port)
            logger.debug("Allocated port %d", port)
            return port
        raise RuntimeError(
            f"No available ports in range {self._port}-{self._port_max}. "
            f"Too many concurrent sessions ({len(self._used_ports)})."
        )

    def _release_port(self, port: int) -> None:
        """Return port to available pool."""
        self._used_ports.discard(port)
        logger.debug("Released port %d", port)

    def _get_browser_cdp(self, instance: ChromeInstance) -> PersistentCDPClient | None:
        """Get the browser-level CDP client for an instance.

        Isolated mode instances have their own browser CDP.
        Profile mode instances use the shared browser CDP.
        """
        if instance.owns_chrome:
            return instance.instance_browser_cdp
        return self._browser_cdp

    async def _find_chrome_path(self) -> str:
        """Find Chrome or Edge executable on Windows."""
        if self._chrome_path:
            return self._chrome_path

        find_chrome_ps = """
        $paths = @(
            "${env:PROGRAMFILES(x86)}\\Microsoft\\Edge\\Application\\msedge.exe",
            "$env:PROGRAMFILES\\Microsoft\\Edge\\Application\\msedge.exe",
            "$env:PROGRAMFILES\\Google\\Chrome\\Application\\chrome.exe",
            "${env:PROGRAMFILES(x86)}\\Google\\Chrome\\Application\\chrome.exe",
            "$env:LOCALAPPDATA\\Google\\Chrome\\Application\\chrome.exe"
        )
        foreach ($p in $paths) { if (Test-Path $p) { Write-Output $p; break } }
        """
        result = run_windows_command(find_chrome_ps, timeout=10.0)
        chrome_path = result.stdout.strip() if result.returncode == 0 else None

        if not chrome_path:
            raise RuntimeError("Chrome/Edge not found on Windows")

        self._chrome_path = chrome_path
        logger.info("Found browser at: %s", chrome_path)
        return chrome_path

    def _setup_event_handlers(self, instance: ChromeInstance) -> None:
        """Set up CDP event handlers for an instance."""
        if not instance.cdp:
            return

        # Console messages
        def on_console(params: dict[str, Any]) -> None:
            args = params.get("args", [])
            text_parts = []
            for arg in args:
                if "value" in arg:
                    text_parts.append(str(arg["value"]))
                elif "description" in arg:
                    text_parts.append(arg["description"])
                elif "preview" in arg:
                    # Object preview
                    preview = arg["preview"]
                    text_parts.append(preview.get("description", str(preview)))

            instance.add_console_message(
                msg_type=params.get("type", "log"),
                text=" ".join(text_parts) if text_parts else "",
                timestamp=params.get("timestamp"),
                stack_trace=params.get("stackTrace", {}).get("callFrames"),
                args=args,
            )

        instance.cdp.on("Runtime.consoleAPICalled", on_console)

        # Network requests
        def on_request_will_be_sent(params: dict[str, Any]) -> None:
            request_id = params["requestId"]
            request = params["request"]

            instance.add_network_request(
                request_id,
                NetworkRequest(
                    request_id=request_id,
                    url=request["url"],
                    method=request["method"],
                    timestamp=params.get("timestamp"),
                    type=params.get("type"),
                    headers=request.get("headers", {}),
                    post_data=request.get("postData"),
                ),
            )

        def on_response_received(params: dict[str, Any]) -> None:
            request_id = params["requestId"]
            if request_id in instance.network_requests:
                response = params["response"]
                req = instance.network_requests[request_id]
                req.response = {
                    "status": response["status"],
                    "statusText": response.get("statusText", ""),
                    "headers": response.get("headers", {}),
                    "mimeType": response.get("mimeType"),
                }

        instance.cdp.on("Network.requestWillBeSent", on_request_will_be_sent)
        instance.cdp.on("Network.responseReceived", on_response_received)

        # Dialogs
        def on_dialog_opening(params: dict[str, Any]) -> None:
            instance.set_dialog(
                DialogInfo(
                    type=params["type"],
                    message=params["message"],
                    default_prompt=params.get("defaultPrompt"),
                    url=params.get("url"),
                )
            )
            logger.info(
                "Session %s: Dialog opened - type=%s, message=%s",
                instance.session_id,
                params["type"],
                params["message"][:50],
            )

        def on_dialog_closed(params: dict[str, Any]) -> None:
            instance.set_dialog(None)

        instance.cdp.on("Page.javascriptDialogOpening", on_dialog_opening)
        instance.cdp.on("Page.javascriptDialogClosed", on_dialog_closed)

        # Navigation (clear page state)
        def on_frame_navigated(params: dict[str, Any]) -> None:
            frame = params.get("frame", {})
            if frame.get("parentId") is None:
                # Main frame navigation - clear page-specific state
                instance.clear_page_state()
                logger.debug("Session %s: Main frame navigated, cleared state", instance.session_id)

        instance.cdp.on("Page.frameNavigated", on_frame_navigated)

        # Trace events (for performance)
        def on_trace_data_collected(params: dict[str, Any]) -> None:
            if instance.trace_active:
                instance.trace_events.extend(params.get("value", []))

        def on_tracing_complete(params: dict[str, Any]) -> None:
            instance.trace_active = False
            logger.info("Session %s: Tracing complete", instance.session_id)

        instance.cdp.on("Tracing.dataCollected", on_trace_data_collected)
        instance.cdp.on("Tracing.tracingComplete", on_tracing_complete)

    async def _connect_cdp(self, instance: ChromeInstance, target_id: str) -> None:
        """Establish persistent CDP connection for a target.

        Tries multiple WebSocket URLs in order:
        1. Original URL (localhost — works via WSL2 localhostForwarding)
        2. Rewritten URL with Windows host IP (fallback)

        Raises:
            RuntimeError: If no connection method is available.
            ConnectionError: If all connection attempts fail.
        """
        if not instance.proxy:
            raise RuntimeError("No proxy available to discover targets")

        targets = await instance.proxy.list_targets()
        target = next((t for t in targets if t.get("id") == target_id), None)
        if not target:
            raise RuntimeError(f"Target {target_id} not found")

        original_ws_url = target.get("webSocketDebuggerUrl", "")
        if not original_ws_url:
            raise RuntimeError(f"No WebSocket URL for target {target_id}")

        if instance.cdp and instance.cdp.is_connected:
            await instance.cdp.disconnect()

        last_error: Exception | None = None
        if self._direct_tcp_works:
            candidate_urls = self._build_ws_candidates(original_ws_url)
            for attempt in range(3):
                if attempt > 0:
                    logger.debug(
                        "Session %s: page CDP retry %d/3",
                        instance.session_id,
                        attempt + 1,
                    )
                    await asyncio.sleep(1)
                    # Re-discover target in case URL changed
                    targets = await instance.proxy.list_targets()
                    target = next((t for t in targets if t.get("id") == target_id), None)
                    if target:
                        new_ws = target.get("webSocketDebuggerUrl", "")
                        if new_ws:
                            candidate_urls = self._build_ws_candidates(new_ws)

                for ws_url in candidate_urls:
                    try:
                        logger.debug("Trying direct CDP connection: %s", ws_url)
                        client = PersistentCDPClient(ws_url, timeout=5.0)
                        await client.connect()
                        instance.cdp = client
                        await enable_domains(instance.cdp, ["Page", "Runtime", "Network", "DOM"])
                        self._setup_event_handlers(instance)
                        logger.info(
                            "Session %s: CDP connected to target %s via %s",
                            instance.session_id,
                            target_id,
                            ws_url,
                        )
                        return
                    except Exception as e:
                        logger.debug("Direct CDP failed for %s: %s", ws_url, e)
                        last_error = e
            self._direct_tcp_works = False
            logger.info("Direct TCP connections failed; future attempts will use relay directly")

        if is_wsl():
            try:
                logger.info("Trying PowerShell CDP relay for %s", original_ws_url)
                relay = PowerShellCDPRelay(original_ws_url)
                await relay.connect()
                instance.cdp = relay
                await enable_domains(relay, ["Page", "Runtime", "Network", "DOM"])
                self._setup_event_handlers(instance)
                logger.info(
                    "Session %s: CDP connected via PowerShell relay to target %s",
                    instance.session_id,
                    target_id,
                )
                return
            except Exception as e:
                logger.warning("PowerShell CDP relay failed: %s", e)
                last_error = e

        raise ConnectionError(
            f"All CDP connection attempts failed for target {target_id}: {last_error}"
        )

    @staticmethod
    def _build_ws_candidates(original_ws_url: str) -> list[str]:
        """Build ordered list of WebSocket URLs to try.

        Non-WSL: just the original URL.
        WSL mirrored: localhost only (shares Windows network stack).
        WSL NAT: localhost first, then Windows host IP.
        """
        if not is_wsl():
            return [original_ws_url]

        if is_mirrored_networking():
            return [original_ws_url]

        candidates = [original_ws_url]

        windows_host = get_windows_host_ip()
        if windows_host not in ("127.0.0.1", "localhost"):
            rewritten = re.sub(
                r"ws://(127\.0\.0\.1|localhost)(:\d+)",
                f"ws://{windows_host}\\2",
                original_ws_url,
            )
            if rewritten != original_ws_url:
                candidates.append(rewritten)

        return candidates

    async def _try_adopt_existing_chrome(self) -> bool:
        """Try to adopt an existing Chrome already running on the debugging port.

        Another MCP process (from a different chat session) may have launched
        Chrome on this port. Instead of launching a competing instance, we
        connect to the existing one.

        Returns:
            True if we successfully adopted an existing Chrome.
        """
        try:
            probe = CDPProxyClient(self._port)
            version = await probe.get_version()
            if not version:
                return False

            logger.info(
                "Found existing Chrome on port %d: %s (adopting, profile_mode=%s)",
                self._port,
                version.get("Browser", "unknown"),
                self._profile_mode,
            )

            self._shared_proxy = probe
            self._shared_pid = None
            self._shared_user_data_dir = None

            await self._connect_browser_cdp()
            return True
        except Exception as e:
            logger.debug("No adoptable Chrome on port %d: %s", self._port, e)
            return False

    async def _ensure_shared_chrome(self) -> None:
        """Ensure the shared Chrome process and browser CDP are available."""
        if self._shared_proxy:
            try:
                version = await self._shared_proxy.get_version()
                if version:
                    if not self._browser_cdp or not self._browser_cdp.is_connected:
                        await self._connect_browser_cdp()
                    return
            except Exception as e:
                logger.debug("Shared Chrome health check failed: %s", e)

            logger.warning("Shared Chrome appears to have died; invalidating sessions")
            await self._invalidate_all_sessions()

        # Before launching a new Chrome, check if one is already running
        # (e.g. launched by another MCP process / chat session)
        if await self._try_adopt_existing_chrome():
            return

        chrome_path = await self._find_chrome_path()

        user_data_dir: str | None = None
        owns_user_data = False

        if self._profile_mode == "profile":
            get_ud_ps = 'Write-Output "$env:LOCALAPPDATA\\Google\\Chrome\\User Data"'
            result = run_windows_command(get_ud_ps, timeout=10.0)
            user_data_dir = result.stdout.strip() if result.returncode == 0 else None
            if not user_data_dir:
                raise RuntimeError("Failed to resolve Chrome User Data directory")
        else:
            create_temp_ps = (
                '$temp = Join-Path $env:TEMP ("chrome-mcp-" + '
                "[System.IO.Path]::GetRandomFileName()); "
                "New-Item -ItemType Directory -Path $temp -Force | Out-Null; "
                "Write-Output $temp"
            )
            result = run_windows_command(create_temp_ps, timeout=10.0)
            user_data_dir = result.stdout.strip() if result.returncode == 0 else None
            if not user_data_dir:
                raise RuntimeError("Failed to create temp directory on Windows")
            owns_user_data = True

        logger.info(
            "Launching shared Chrome on port %d (profile_mode=%s, user_data_dir=%s)",
            self._port,
            self._profile_mode,
            user_data_dir,
        )

        args = [
            f"--remote-debugging-port={self._port}",
            "--remote-debugging-address=0.0.0.0",
            "--remote-allow-origins=*",
            f"--user-data-dir={user_data_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-popup-blocking",
        ]
        if self._profile_mode == "profile" and self._profile_name:
            args.append(f"--profile-directory={self._profile_name}")
        if self._headless:
            args.append("--headless=new")

        arg_parts = []
        for arg in args:
            if " " in arg:
                arg_parts.append(f'"{arg}"')
            else:
                arg_parts.append(arg)
        args_line = " ".join(arg_parts)
        launch_ps = (
            f'$proc = Start-Process -FilePath "{chrome_path}" '
            f"-ArgumentList '{args_line}' -PassThru; "
            "Write-Output $proc.Id"
        )
        logger.debug("Chrome launch command: %s", launch_ps)
        result = run_windows_command(launch_ps, timeout=10.0)

        shared_pid: int | None = None
        if result.returncode == 0 and result.stdout.strip():
            try:
                shared_pid = int(result.stdout.strip())
                logger.info("Shared Chrome launched with PID %d", shared_pid)
            except ValueError:
                logger.warning("Could not parse shared Chrome PID: %s", result.stdout)

        shared_proxy = CDPProxyClient(self._port)

        for _attempt in range(30):
            await asyncio.sleep(1)
            version = await shared_proxy.get_version()
            if version:
                logger.info(
                    "Shared Chrome ready on port %d: %s",
                    self._port,
                    version.get("Browser", "unknown"),
                )
                break
        else:
            raise RuntimeError(f"Chrome did not start within 30 seconds on port {self._port}")

        self._shared_pid = shared_pid
        self._shared_user_data_dir = user_data_dir if owns_user_data else None
        self._shared_proxy = shared_proxy

        try:
            await self._connect_browser_cdp()
        except Exception:
            await self._kill_shared_chrome()
            raise

    async def _connect_browser_cdp(self) -> None:
        """Connect browser-level CDP for BrowserContext management.

        Retries up to 3 times with 1s delay to handle the race condition
        where Chrome's HTTP endpoint is ready but WebSocket returns 404.
        """
        if not self._shared_proxy:
            raise RuntimeError("Shared Chrome proxy is not initialized")

        if self._browser_cdp:
            with contextlib.suppress(Exception):
                await self._browser_cdp.disconnect()
            self._browser_cdp = None

        last_error: Exception | None = None

        for attempt in range(3):
            if attempt > 0:
                logger.debug("Browser CDP connection retry %d/3", attempt + 1)
                await asyncio.sleep(1)

            browser_ws_url = await self._shared_proxy.get_browser_ws_url()
            if not browser_ws_url:
                last_error = RuntimeError("Failed to get browser WebSocket URL")
                continue

            for ws_url in self._build_ws_candidates(browser_ws_url):
                try:
                    client = PersistentCDPClient(ws_url, timeout=5.0)
                    await client.connect()
                    self._browser_cdp = client
                    logger.info("Connected browser CDP via %s", ws_url)
                    return
                except Exception as e:
                    last_error = e
                    logger.debug("Browser CDP connection failed for %s: %s", ws_url, e)

        # Fallback: try PowerShell relay for browser-level CDP
        browser_ws_url = await self._shared_proxy.get_browser_ws_url()
        if browser_ws_url:
            try:
                logger.info("Trying PowerShell relay for browser CDP: %s", browser_ws_url)
                relay = PowerShellCDPRelay(browser_ws_url)
                await relay.connect()
                self._browser_cdp = relay
                self._direct_tcp_works = False
                logger.info("Connected browser CDP via PowerShell relay")
                return
            except Exception as e:
                logger.warning("PowerShell relay for browser CDP failed: %s", e)
                last_error = e

        raise ConnectionError(f"Failed to connect browser CDP: {last_error}")

    async def _connect_instance_browser_cdp(self, instance: ChromeInstance) -> None:
        """Connect browser-level CDP for an isolated-mode instance.

        Similar to _connect_browser_cdp but stores on the instance, not shared.
        """
        if not instance.proxy:
            raise RuntimeError("Instance proxy is not initialized")

        if instance.instance_browser_cdp:
            with contextlib.suppress(Exception):
                await instance.instance_browser_cdp.disconnect()
            instance.instance_browser_cdp = None

        last_error: Exception | None = None

        for attempt in range(3):
            if attempt > 0:
                logger.debug(
                    "Instance %s browser CDP retry %d/3",
                    instance.session_id,
                    attempt + 1,
                )
                await asyncio.sleep(1)

            browser_ws_url = await instance.proxy.get_browser_ws_url()
            if not browser_ws_url:
                last_error = RuntimeError("Failed to get browser WebSocket URL")
                continue

            for ws_url in self._build_ws_candidates(browser_ws_url):
                try:
                    client = PersistentCDPClient(ws_url, timeout=5.0)
                    await client.connect()
                    instance.instance_browser_cdp = client
                    logger.info(
                        "Session %s: connected instance browser CDP via %s",
                        instance.session_id,
                        ws_url,
                    )
                    return
                except Exception as e:
                    last_error = e
                    logger.debug("Instance browser CDP failed for %s: %s", ws_url, e)

        raise ConnectionError(
            f"Failed to connect instance browser CDP for {instance.session_id}: {last_error}"
        )

    async def _close_default_tabs(self, keep_target_id: str) -> None:
        """Close Chrome's default about:blank tab after first session creation.

        Runs ONCE, only when this process launched Chrome (_shared_pid set).
        Skipped when Chrome was adopted from another process.
        """
        if self._default_tabs_closed or self._shared_pid is None or not self._browser_cdp:
            return
        self._default_tabs_closed = True

        try:
            result = await self._browser_cdp.send("Target.getTargets", {})
            for target in result.get("targetInfos", []):
                tid = target.get("targetId")
                if target.get("type") == "page" and tid and tid != keep_target_id:
                    with contextlib.suppress(Exception):
                        await self._browser_cdp.send("Target.closeTarget", {"targetId": tid})
                    logger.debug("Closed default tab %s", tid)
        except Exception as e:
            logger.debug("Failed to close default tabs: %s", e)

    async def _invalidate_all_sessions(self) -> None:
        """Invalidate all sessions after shared Chrome failure."""
        for instance in self._instances.values():
            await self._disconnect_cdp(instance)
        self._instances.clear()

        if self._browser_cdp:
            with contextlib.suppress(Exception):
                await self._browser_cdp.disconnect()

        self._browser_cdp = None
        self._shared_proxy = None
        self._shared_pid = None
        self._shared_user_data_dir = None
        self._direct_tcp_works = True

    async def _kill_shared_chrome(self) -> None:
        """Kill shared Chrome process and clean up resources."""
        if self._browser_cdp:
            with contextlib.suppress(Exception):
                await self._browser_cdp.disconnect()

        if self._shared_pid:
            logger.info("Killing shared Chrome PID %d", self._shared_pid)
            kill_ps = f"Stop-Process -Id {self._shared_pid} -Force -ErrorAction SilentlyContinue"
            try:
                run_windows_command(kill_ps, timeout=10.0)
            except Exception as e:
                logger.warning("Error killing shared Chrome PID %d: %s", self._shared_pid, e)

        if self._shared_user_data_dir:
            cleanup_ps = (
                f'Remove-Item -Path "{self._shared_user_data_dir}" '
                "-Recurse -Force -ErrorAction SilentlyContinue"
            )
            try:
                run_windows_command(cleanup_ps, timeout=10.0)
            except Exception as e:
                logger.warning("Error cleaning up %s: %s", self._shared_user_data_dir, e)

        self._browser_cdp = None
        self._shared_proxy = None
        self._shared_pid = None
        self._shared_user_data_dir = None
        self._direct_tcp_works = True
        self._default_tabs_closed = False

    async def _kill_instance_chrome(self, instance: ChromeInstance) -> None:
        """Kill a per-session Chrome process and clean up its resources."""
        if instance.instance_browser_cdp:
            with contextlib.suppress(Exception):
                await instance.instance_browser_cdp.disconnect()
            instance.instance_browser_cdp = None

        if instance.pid:
            logger.info(
                "Killing Chrome PID %d for session %s",
                instance.pid,
                instance.session_id,
            )
            kill_ps = f"Stop-Process -Id {instance.pid} -Force -ErrorAction SilentlyContinue"
            try:
                run_windows_command(kill_ps, timeout=10.0)
            except Exception as e:
                logger.warning(
                    "Error killing Chrome PID %d for session %s: %s",
                    instance.pid,
                    instance.session_id,
                    e,
                )

        if instance.user_data_dir:
            cleanup_ps = (
                f'Remove-Item -Path "{instance.user_data_dir}" '
                "-Recurse -Force -ErrorAction SilentlyContinue"
            )
            try:
                run_windows_command(cleanup_ps, timeout=10.0)
            except Exception as e:
                logger.warning(
                    "Error cleaning up %s for session %s: %s",
                    instance.user_data_dir,
                    instance.session_id,
                    e,
                )

    async def _disconnect_cdp(self, instance: ChromeInstance) -> None:
        """Disconnect page-level CDP for an instance."""
        if instance.cdp:
            with contextlib.suppress(Exception):
                await instance.cdp.disconnect()
            instance.cdp = None

    async def get_or_create(self, session_id: str) -> ChromeInstance:
        """Get existing Chrome instance or create new one for this session.

        Args:
            session_id: The opencode session identifier.

        Returns:
            ChromeInstance for the requested session.
        """
        if session_id in self._instances:
            instance = self._instances[session_id]

            if instance.owns_chrome:
                # Isolated mode: check this instance's own Chrome health
                if not instance.is_connected and instance.current_target_id:
                    try:
                        if instance.proxy:
                            targets = await instance.proxy.list_targets()
                            target_exists = any(
                                t.get("id") == instance.current_target_id for t in targets
                            )
                        else:
                            target_exists = False
                    except Exception:
                        target_exists = False

                    if target_exists:
                        logger.info("Reconnecting CDP for isolated session %s", session_id)
                        try:
                            await self._connect_cdp(instance, instance.current_target_id)
                        except Exception as e:
                            logger.warning("Failed to reconnect CDP: %s", e)
                        return instance

                    # Tracked tab gone — check if Chrome is still alive
                    page_targets = [t for t in targets if t.get("type") == "page"]
                    if page_targets:
                        # Chrome alive, just our tab was closed — adopt existing tab
                        new_target = page_targets[0]
                        new_target_id = new_target.get("id")
                        logger.info(
                            "Session %s: tracked tab %s closed, adopting existing tab %s (%s)",
                            session_id,
                            instance.current_target_id,
                            new_target_id,
                            new_target.get("url", "unknown"),
                        )
                        instance.current_target_id = new_target_id
                        instance.targets = [str(t["id"]) for t in page_targets if t.get("id")]
                        try:
                            await self._connect_cdp(instance, new_target_id)
                        except Exception as e:
                            logger.warning("Failed to connect to adopted tab: %s", e)
                        return instance

                    # No page targets — Chrome truly died, recreate
                    logger.info(
                        "Session %s: isolated Chrome dead (no page targets), recreating",
                        session_id,
                    )
                    await self._disconnect_cdp(instance)
                    await self._kill_instance_chrome(instance)
                    self._release_port(instance.port)
                    del self._instances[session_id]
                else:
                    return instance
            else:
                # Shared/profile mode: check shared Chrome health
                if not instance.is_connected and instance.current_target_id:
                    try:
                        await self._ensure_shared_chrome()
                        targets = (
                            await self._shared_proxy.list_targets() if self._shared_proxy else []
                        )
                        target_exists = any(
                            t.get("id") == instance.current_target_id for t in targets
                        )
                    except Exception:
                        target_exists = False

                    if target_exists:
                        logger.info("Reconnecting CDP for session %s", session_id)
                        try:
                            await self._connect_cdp(instance, instance.current_target_id)
                        except Exception as e:
                            logger.warning("Failed to reconnect CDP: %s", e)
                        return instance

                    logger.info(
                        "Session %s: target %s no longer exists (Chrome restarted), recreating",
                        session_id,
                        instance.current_target_id,
                    )
                    await self._disconnect_cdp(instance)
                    del self._instances[session_id]
                else:
                    return instance

        record = self._session_store.load(session_id)
        if record is not None:
            instance = await self._try_reconnect_from_record(record)
            if instance is not None:
                self._instances[session_id] = instance
                return instance
            self._session_store.delete(session_id)

        logger.info(
            "Creating new Chrome session %s (profile_mode=%s)", session_id, self._profile_mode
        )

        if self._profile_mode != "profile":
            # Isolated mode: per-session Chrome, retry with new port on failure
            for attempt in range(3):
                try:
                    return await self._create_isolated_session(session_id)
                except Exception as e:
                    logger.warning(
                        "Isolated session creation attempt %d failed: %s",
                        attempt + 1,
                        e,
                    )
                    if attempt == 2:
                        raise
            raise RuntimeError("Isolated session creation failed after retries")
        else:
            # Profile mode: shared Chrome, retry with Chrome restart
            for attempt in range(2):
                try:
                    return await self._create_shared_session(session_id)
                except Exception as e:
                    if attempt == 0:
                        logger.warning(
                            "Session creation failed (%s), restarting Chrome and retrying",
                            e,
                        )
                        await self._invalidate_all_sessions()
                        await self._kill_shared_chrome()
                        continue
                    raise
            raise RuntimeError("Session creation failed after retry")

    async def _create_profile_tab(self) -> tuple[str, int]:
        """Create a tab in the configured Chrome profile in a new window.

        Chrome profile contexts are internal and can't be targeted via
        ``Target.createTarget``. Instead we launch Chrome with
        ``--profile-directory --new-window`` which opens an isolated window
        in the correct profile through Chrome's singleton IPC.

        Returns (targetId, windowId) of the new tab/window.
        """
        if not self._browser_cdp:
            raise RuntimeError("Browser CDP not connected")

        chrome_path = await self._find_chrome_path()

        ud_result = run_windows_command(
            'Write-Output "$env:LOCALAPPDATA\\Google\\Chrome\\MCP Data"',
            timeout=10.0,
        )
        junction_path = ud_result.stdout.strip()
        if not junction_path:
            raise RuntimeError("Failed to resolve MCP Data junction path")

        before_result = await self._browser_cdp.send("Target.getTargets", {})
        before_ids = {t["targetId"] for t in before_result.get("targetInfos", [])}

        profile_dir = self._profile_name
        arg_line = (
            f'--user-data-dir="{junction_path}" '
            f'--profile-directory="{profile_dir}" '
            f"--new-window about:blank"
        )
        launch_ps = f"Start-Process '{chrome_path}' -ArgumentList '{arg_line}'"
        run_windows_command(launch_ps, timeout=10.0)

        target_id: str | None = None
        for _ in range(10):
            await asyncio.sleep(0.5)
            try:
                result = await self._browser_cdp.send("Target.getTargets", {})
                for t in result.get("targetInfos", []):
                    if t["targetId"] not in before_ids and t.get("type") == "page":
                        target_id = t["targetId"]
                        self._profile_context_id = t.get("browserContextId", "")
                        break
                if target_id:
                    break
            except Exception:
                continue

        if not target_id:
            raise RuntimeError(f"Failed to create tab in profile '{self._profile_name}'")

        window_result = await self._browser_cdp.send(
            "Browser.getWindowForTarget", {"targetId": target_id}
        )
        window_id = window_result["windowId"]

        logger.info(
            "Profile '%s' window created: target=%s window=%d ctx=%s",
            self._profile_name,
            target_id[:12],
            window_id,
            (self._profile_context_id or "")[:12],
        )

        return target_id, window_id

    async def _create_isolated_session(self, session_id: str) -> ChromeInstance:
        """Create a new session with its own dedicated Chrome process.

        This is the original architecture: each session gets its own Chrome
        on a unique port with a temp user-data-dir. Chrome's natural first
        tab is used (no forced about:blank, no BrowserContext).
        """
        port = self._allocate_port()

        self._session_store.save(
            SessionRecord(
                session_id=session_id,
                port=port,
                pid=None,
                target_ids=[],
                current_target_id=None,
                profile_mode="isolated",
                created_at=datetime.now().isoformat(),
                browser_context_id=None,
            )
        )

        chrome_path = await self._find_chrome_path()

        # Create temp directory on Windows
        create_temp_ps = (
            '$temp = Join-Path $env:TEMP ("chrome-mcp-" + '
            "[System.IO.Path]::GetRandomFileName()); "
            "New-Item -ItemType Directory -Path $temp -Force | Out-Null; "
            "Write-Output $temp"
        )
        result = run_windows_command(create_temp_ps, timeout=10.0)
        user_data_dir = result.stdout.strip() if result.returncode == 0 else None

        if not user_data_dir:
            self._release_port(port)
            raise RuntimeError("Failed to create temp directory on Windows")

        logger.info(
            "Launching Chrome for session %s on port %d (user_data_dir=%s)",
            session_id,
            port,
            user_data_dir,
        )

        # Build Chrome arguments
        args = [
            f"--remote-debugging-port={port}",
            "--remote-debugging-address=0.0.0.0",
            "--remote-allow-origins=*",
            f"--user-data-dir={user_data_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-popup-blocking",
        ]
        if self._headless:
            args.append("--headless=new")

        arg_parts = []
        for arg in args:
            if " " in arg:
                arg_parts.append(f'"{arg}"')
            else:
                arg_parts.append(arg)
        args_line = " ".join(arg_parts)
        launch_ps = (
            f'$proc = Start-Process -FilePath "{chrome_path}" '
            f"-ArgumentList '{args_line}' -PassThru; "
            "Write-Output $proc.Id"
        )
        logger.debug("Chrome launch command: %s", launch_ps)
        result = run_windows_command(launch_ps, timeout=10.0)

        pid: int | None = None
        if result.returncode == 0 and result.stdout.strip():
            try:
                pid = int(result.stdout.strip())
                logger.info("Chrome launched with PID %d for session %s", pid, session_id)
            except ValueError:
                logger.warning("Could not parse Chrome PID: %s", result.stdout)

        # Wait for Chrome to be ready
        proxy = CDPProxyClient(port)
        for _attempt in range(30):
            await asyncio.sleep(1)
            version = await proxy.get_version()
            if version:
                logger.info(
                    "Chrome ready on port %d for session %s: %s",
                    port,
                    session_id,
                    version.get("Browser", "unknown"),
                )
                break
        else:
            # Chrome didn't start — clean up
            if pid:
                kill_ps = f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue"
                with contextlib.suppress(Exception):
                    run_windows_command(kill_ps, timeout=10.0)
            cleanup_ps = (
                f'Remove-Item -Path "{user_data_dir}" -Recurse -Force -ErrorAction SilentlyContinue'
            )
            with contextlib.suppress(Exception):
                run_windows_command(cleanup_ps, timeout=10.0)
            self._release_port(port)
            raise RuntimeError(f"Chrome did not start within 30 seconds on port {port}")

        # Grab Chrome's natural first tab (whatever Chrome opened — NOT forced about:blank)
        targets = await proxy.list_targets()
        page_targets = [t for t in targets if t.get("type") == "page"]

        if not page_targets:
            # Shouldn't happen, but create a page if Chrome has none
            new_page = await proxy.new_page()
            if new_page:
                initial_target_id = new_page.get("id")
            else:
                self._release_port(port)
                raise RuntimeError("Chrome launched with no page targets")
        else:
            initial_target_id = page_targets[0].get("id")

        if not initial_target_id:
            self._release_port(port)
            raise RuntimeError("Failed to get initial target ID")

        instance = ChromeInstance(
            session_id=session_id,
            port=port,
            pid=pid,
            user_data_dir=user_data_dir,
            proxy=proxy,
            browser_context_id=None,  # No BrowserContext in isolated mode
            current_target_id=initial_target_id,
            targets=[initial_target_id],
            owns_chrome=True,
        )

        # Connect browser-level CDP for this instance
        try:
            await self._connect_instance_browser_cdp(instance)
        except Exception as e:
            logger.warning(
                "Session %s: failed to connect instance browser CDP: %s",
                session_id,
                e,
            )

        # Connect page-level CDP
        try:
            await self._connect_cdp(instance, initial_target_id)
        except Exception as e:
            logger.warning(
                "Failed to establish persistent CDP connection, falling back to proxy: %s",
                e,
            )

        if instance.is_connected:
            logger.info(
                "Session %s: persistent CDP connection established (isolated, port %d)",
                session_id,
                port,
            )
        elif instance.proxy:
            logger.info(
                "Session %s: using proxy-only mode (isolated, port %d)",
                session_id,
                port,
            )

        self._instances[session_id] = instance
        self._session_store.save(
            SessionRecord(
                session_id=instance.session_id,
                port=instance.port,
                pid=instance.pid,
                target_ids=list(instance.targets),
                current_target_id=instance.current_target_id,
                profile_mode="isolated",
                browser_context_id=instance.browser_context_id,
            )
        )
        return instance

    async def _create_shared_session(self, session_id: str) -> ChromeInstance:
        """Create a new session in the shared Chrome process (profile mode)."""
        await self._ensure_shared_chrome()

        if not self._browser_cdp or not self._shared_proxy:
            raise RuntimeError("Shared Chrome is not available")

        browser_context_id: str | None = None
        window_id: int | None = None
        use_profile_cli = self._profile_mode == "profile" and bool(self._profile_name)

        try:
            if use_profile_cli:
                initial_target_id, window_id = await self._create_profile_tab()
                browser_context_id = self._profile_context_id
                logger.info(
                    "Session %s: profile '%s' tab %s window=%d",
                    session_id,
                    self._profile_name,
                    initial_target_id[:12],
                    window_id,
                )
            else:
                target_result = await self._browser_cdp.send(
                    "Target.createTarget",
                    {"url": "about:blank"},
                )
                initial_target_id = target_result["targetId"]
                logger.info(
                    "Session %s: default browser context (profile_mode=%s)",
                    session_id,
                    self._profile_mode,
                )

            await self._close_default_tabs(initial_target_id)

            instance = ChromeInstance(
                session_id=session_id,
                port=self._port,
                pid=self._shared_pid,
                user_data_dir=self._shared_user_data_dir or "",
                proxy=self._shared_proxy,
                browser_context_id=browser_context_id,
                current_target_id=initial_target_id,
                targets=[initial_target_id],
                window_id=window_id,
                owns_chrome=False,
            )

            try:
                await self._connect_cdp(instance, initial_target_id)
            except Exception as e:
                logger.warning(
                    "Failed to establish persistent CDP connection, falling back to proxy: %s",
                    e,
                )

            if instance.is_connected:
                logger.info(
                    "Session %s: persistent CDP connection established",
                    session_id,
                )
            elif instance.proxy:
                logger.info(
                    "Session %s: using proxy-only mode (no persistent CDP)",
                    session_id,
                )
            else:
                logger.error(
                    "Session %s: no connection method available",
                    session_id,
                )

            self._instances[session_id] = instance
            self._session_store.save(
                SessionRecord(
                    session_id=instance.session_id,
                    port=instance.port,
                    pid=instance.pid,
                    target_ids=list(instance.targets),
                    current_target_id=instance.current_target_id,
                    profile_mode="profile",
                    browser_context_id=instance.browser_context_id,
                )
            )
            return instance
        except Exception:
            if browser_context_id and self._browser_cdp and self._browser_cdp.is_connected:
                with contextlib.suppress(Exception):
                    await self._browser_cdp.send(
                        "Target.disposeBrowserContext",
                        {"browserContextId": browser_context_id},
                    )
            raise

    async def destroy(self, session_id: str) -> None:
        """Destroy a session's Chrome instance.

        Args:
            session_id: The session to destroy.

        Raises:
            KeyError: If session not found.
        """
        instance = self._instances.pop(session_id)
        await self._disconnect_cdp(instance)

        if instance.owns_chrome:
            logger.info(
                "Detached isolated Chrome session %s (port %d, Chrome stays alive)",
                session_id,
                instance.port,
            )
        elif (
            not instance.browser_context_id and self._browser_cdp and self._browser_cdp.is_connected
        ):
            for target_id in instance.targets:
                with contextlib.suppress(Exception):
                    await self._browser_cdp.send(
                        "Target.closeTarget",
                        {"targetId": target_id},
                    )
            logger.info(
                "Session %s: closed %d tab(s) in profile mode",
                session_id,
                len(instance.targets),
            )
        elif instance.browser_context_id and self._browser_cdp and self._browser_cdp.is_connected:
            try:
                await self._browser_cdp.send(
                    "Target.disposeBrowserContext",
                    {"browserContextId": instance.browser_context_id},
                )
                logger.info(
                    "Session %s: disposed browser context %s",
                    session_id,
                    instance.browser_context_id,
                )
            except Exception as e:
                logger.warning(
                    "Session %s: failed to dispose browser context %s: %s",
                    session_id,
                    instance.browser_context_id,
                    e,
                )
        else:
            logger.info("Detached Chrome session %s", session_id)

    async def cleanup_all(self) -> None:
        """Disconnect all CDP connections without killing Chrome.

        Chrome processes stay alive for reconnection on next MCP start.
        Session records are preserved on disk.
        """
        logger.info("Disconnecting %d Chrome session(s) (Chrome stays alive)", len(self._instances))
        for session_id in list(self._instances.keys()):
            try:
                instance = self._instances.pop(session_id)
                await self._disconnect_cdp(instance)
                if instance.instance_browser_cdp:
                    with contextlib.suppress(Exception):
                        await instance.instance_browser_cdp.disconnect()
                    instance.instance_browser_cdp = None
            except Exception as e:
                logger.warning("Error disconnecting session %s: %s", session_id, e)

        if self._browser_cdp and self._browser_cdp.is_connected:
            with contextlib.suppress(Exception):
                await self._browser_cdp.close()
            self._browser_cdp = None

    def list_sessions(self) -> dict[str, dict[str, Any]]:
        """List all active sessions.

        Returns:
            Dict mapping session_id to session info.
        """
        result = {}
        for session_id, instance in self._instances.items():
            result[session_id] = {
                "session_id": session_id,
                "port": instance.port,
                "pid": instance.pid,
                "browser_context_id": instance.browser_context_id,
                "tab_count": len(instance.targets),
                "current_target_id": instance.current_target_id,
                "created_at": instance.created_at.isoformat(),
                "connected": instance.is_connected,
                "console_count": len(instance.console_messages),
                "network_count": len(instance.network_requests),
                "owns_chrome": instance.owns_chrome,
            }
        return result

    # --- Tab operations (within a session's Chrome) ---

    async def _poll_new_target(
        self, before_ids: set[str], timeout: float = 3.0, interval: float = 0.3
    ) -> str | None:
        iterations = int(timeout / interval)
        for _ in range(max(iterations, 1)):
            await asyncio.sleep(interval)
            if not self._browser_cdp:
                return None
            result = await self._browser_cdp.send("Target.getTargets", {})
            for t in result.get("targetInfos", []):
                if t["targetId"] not in before_ids and t.get("type") == "page":
                    return t["targetId"]
        return None

    async def _verify_target_window(self, target_id: str, expected_window: int) -> bool:
        if not self._browser_cdp:
            return False
        try:
            result = await self._browser_cdp.send(
                "Browser.getWindowForTarget", {"targetId": target_id}
            )
            return result.get("windowId") == expected_window
        except Exception:
            return False

    async def create_tab(self, session_id: str, url: str = "about:blank") -> str:
        """Create a new tab in a session's Chrome.

        Isolated mode: simple Target.createTarget (own Chrome, no confusion).
        Profile mode: 3-tier fallback for window placement.
        """
        instance = self._instances[session_id]

        if instance.owns_chrome:
            # Isolated mode: use instance's own browser CDP
            browser_cdp = instance.instance_browser_cdp
            if not browser_cdp or not browser_cdp.is_connected:
                # Try to reconnect
                await self._connect_instance_browser_cdp(instance)
                browser_cdp = instance.instance_browser_cdp
            if not browser_cdp:
                raise RuntimeError("Instance browser CDP is not connected")

            result = await browser_cdp.send(
                "Target.createTarget",
                {"url": url},
            )
            new_target_id = result["targetId"]
        elif instance.window_id is not None:
            # Profile mode with window scoping
            if not self._browser_cdp or not self._browser_cdp.is_connected:
                await self._ensure_shared_chrome()
            if not self._browser_cdp:
                raise RuntimeError("Browser CDP is not connected")
            new_target_id = await self._create_profile_mode_tab(instance, url)
        else:
            # Shared mode without window scoping
            if not self._browser_cdp or not self._browser_cdp.is_connected:
                await self._ensure_shared_chrome()
            if not self._browser_cdp:
                raise RuntimeError("Browser CDP is not connected")

            create_params: dict[str, Any] = {"url": url}
            if instance.browser_context_id:
                create_params["browserContextId"] = instance.browser_context_id

            result = await self._browser_cdp.send(
                "Target.createTarget",
                create_params,
            )
            new_target_id = result["targetId"]

        instance.targets.append(new_target_id)
        await self.switch_tab(session_id, new_target_id)

        logger.info(
            "Session %s: created tab %s -> %s",
            session_id,
            new_target_id,
            url,
        )
        return new_target_id

    async def _create_profile_mode_tab(self, instance: ChromeInstance, url: str) -> str:
        import json as _json

        before_result = await self._browser_cdp.send("Target.getTargets", {})  # type: ignore[union-attr]
        before_ids = {t["targetId"] for t in before_result.get("targetInfos", [])}

        # Tier 1: window.open() with userGesture bypasses popup blocker
        # and guarantees same-window placement
        if instance.cdp and instance.cdp.is_connected:
            try:
                safe_url_js = _json.dumps(url)
                await instance.cdp.send(
                    "Runtime.evaluate",
                    {
                        "expression": f"window.open({safe_url_js}, '_blank')",
                        "userGesture": True,
                    },
                )
                target_id = await self._poll_new_target(before_ids, timeout=5.0, interval=0.5)
                if target_id:
                    logger.info(
                        "Session %s: tab created via window.open (tier 1)",
                        instance.session_id,
                    )
                    return target_id
                logger.warning(
                    "Session %s: window.open with userGesture produced no target, falling back",
                    instance.session_id,
                )
            except Exception as exc:
                logger.warning(
                    "Session %s: window.open failed (%s), falling back",
                    instance.session_id,
                    exc,
                )

        # Tier 2: Target.createTarget with profile browserContextId —
        # may fail ("Failed to find browser context") since profile contexts
        # aren't in CDP's DevToolsBrowserContext map
        if self._profile_context_id:
            try:
                result = await self._browser_cdp.send(  # type: ignore[union-attr]
                    "Target.createTarget",
                    {"url": url, "browserContextId": self._profile_context_id},
                )
                target_id = result["targetId"]
                logger.info(
                    "Session %s: tab created via Target.createTarget (tier 2)",
                    instance.session_id,
                )
                return target_id
            except Exception as exc:
                logger.warning(
                    "Session %s: Target.createTarget with browserContextId "
                    "failed (%s), falling back to CLI",
                    instance.session_id,
                    exc,
                )

        # Tier 3: Chrome CLI — reliable but may land in wrong window
        try:
            chrome_path = await self._find_chrome_path()
            ud_result = run_windows_command(
                'Write-Output "$env:LOCALAPPDATA\\Google\\Chrome\\MCP Data"',
                timeout=10.0,
            )
            junction_path = ud_result.stdout.strip()
            if not junction_path:
                raise RuntimeError("Failed to resolve MCP Data junction path")

            before_result = await self._browser_cdp.send(  # type: ignore[union-attr]
                "Target.getTargets", {}
            )
            before_ids = {t["targetId"] for t in before_result.get("targetInfos", [])}

            safe_url_cli = url.replace("'", "''")
            arg_line = (
                f'--user-data-dir="{junction_path}" '
                f'--profile-directory="{self._profile_name}" '
                f'"{safe_url_cli}"'
            )
            launch_ps = f"Start-Process '{chrome_path}' -ArgumentList '{arg_line}'"
            run_windows_command(launch_ps, timeout=10.0)

            target_id = await self._poll_new_target(before_ids, timeout=5.0, interval=0.5)
            if target_id:
                logger.info(
                    "Session %s: tab created via Chrome CLI (tier 3)",
                    instance.session_id,
                )
                return target_id
        except Exception as exc:
            logger.error(
                "Session %s: Chrome CLI tab creation failed: %s",
                instance.session_id,
                exc,
            )

        raise RuntimeError(f"All tab creation methods failed for session {instance.session_id}")

    async def switch_tab(self, session_id: str, target_id: str) -> None:
        """Switch the active tab in a session's Chrome.

        Args:
            session_id: The session to switch tabs in.
            target_id: The target_id to switch to.

        Raises:
            KeyError: If session not found.
            ValueError: If target_id not in this session.
        """
        instance = self._instances[session_id]

        if target_id not in instance.targets:
            raise ValueError(
                f"Target {target_id} does not belong to session {session_id}. "
                f"Available: {instance.targets}"
            )

        # Disconnect from old tab
        if instance.cdp:
            with contextlib.suppress(Exception):
                await instance.cdp.disconnect()
            instance.cdp = None

        # Activate target using the correct browser CDP
        browser_cdp = self._get_browser_cdp(instance)
        if browser_cdp and browser_cdp.is_connected:
            try:
                await browser_cdp.send(
                    "Target.activateTarget",
                    {"targetId": target_id},
                )
            except Exception as e:
                logger.debug(
                    "Failed to activate target %s for session %s: %s",
                    target_id,
                    session_id,
                    e,
                )

        instance.current_target_id = target_id
        instance.clear_page_state()

        # Connect to new tab
        try:
            await self._connect_cdp(instance, target_id)
        except Exception as e:
            logger.warning("Failed to connect CDP to new tab: %s", e)

        logger.info("Session %s: switched to tab %s", session_id, target_id)

    async def close_tab(self, session_id: str, target_id: str) -> None:
        """Close a tab in a session's Chrome.

        Args:
            session_id: The session that owns the tab.
            target_id: The target_id to close.

        Raises:
            KeyError: If session not found.
            ValueError: If target_id not in session or is the last tab.
        """
        instance = self._instances[session_id]

        if target_id not in instance.targets:
            raise ValueError(f"Target {target_id} does not belong to session {session_id}")

        if len(instance.targets) <= 1:
            raise ValueError(
                f"Cannot close the last tab in session {session_id}. "
                "Use destroy() to close the entire session."
            )

        # If closing current tab, disconnect CDP first
        if instance.current_target_id == target_id and instance.cdp:
            await instance.cdp.disconnect()
            instance.cdp = None

        # Close the target via proxy
        if instance.proxy:
            await instance.proxy.close_page(target_id)

        # Update state
        instance.targets.remove(target_id)

        # Switch to another tab if we closed the current one
        if instance.current_target_id == target_id:
            new_target_id = instance.targets[0]
            instance.current_target_id = new_target_id
            instance.clear_page_state()

            # Connect to new tab
            try:
                await self._connect_cdp(instance, new_target_id)
            except Exception as e:
                logger.warning("Failed to connect CDP to new tab: %s", e)

            logger.info("Session %s: auto-switched to tab %s", session_id, new_target_id)

        logger.info("Session %s: closed tab %s", session_id, target_id)

    async def list_tabs(self, session_id: str) -> list[dict[str, Any]]:
        """List all tabs in a session's Chrome.

        Args:
            session_id: The session to list tabs for.

        Returns:
            List of tab info dicts.

        Raises:
            KeyError: If session not found.
        """
        instance = self._instances[session_id]

        if not instance.proxy:
            return []

        all_targets = await instance.proxy.list_targets()
        session_targets = [t for t in all_targets if t.get("id") in instance.targets]

        tabs = []
        for target in session_targets:
            tabs.append(
                {
                    "id": target.get("id"),
                    "title": target.get("title", ""),
                    "url": target.get("url", ""),
                    "is_current": target.get("id") == instance.current_target_id,
                }
            )

        return tabs
