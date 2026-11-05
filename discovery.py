"""
discovery.py — mDNS service registration and browse for D-HLPE.

RFC 6762 defines multicast DNS so a service is found by name rather than
by a DHCP-assigned address that changes on lease renewal. The service
type is _dhlpe._tcp.local.

browse() uses threading.Event().wait() rather than time.sleep() so that
KeyboardInterrupt unwinds through the finally block and closes the
Zeroconf socket. Without this, Ctrl-C during the wait leaks a UDP socket
on port 5353 and leaves a daemon thread running; the next browse() call
then fails with "address already in use".

Citations:
  RFC 6762: https://www.rfc-editor.org/rfc/rfc6762
  python-zeroconf: https://pypi.org/project/zeroconf/
  threading.Event: https://docs.python.org/3/library/threading.html#threading.Event
"""

import socket
import threading
from typing import List

try:
    from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf
except ImportError:
    ServiceBrowser = ServiceInfo = Zeroconf = None

SERVICE_TYPE = "_dhlpe._tcp.local."


def _local_ip() -> str:
    """
    Return the IP of the default-route interface.

    The connect() call sends no packets. It only asks the kernel which
    local address would be used to reach 192.0.2.1 (TEST-NET-1, RFC 5737,
    guaranteed never to be routed). On a host with a real LAN interface
    this returns the LAN address; on a host with no default route it
    returns 127.0.0.1.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def register(port: int, node_name: str) -> "Zeroconf":
    """
    Register _dhlpe._tcp.local. for this worker.

    Returns the Zeroconf instance. The caller must keep a reference and
    call .close() on shutdown; worker_daemon.py does this from the
    lifespan shutdown hook.
    """
    if Zeroconf is None:
        raise RuntimeError("zeroconf is not installed")
    zc = Zeroconf()
    info = ServiceInfo(
        SERVICE_TYPE,
        f"{node_name}.{SERVICE_TYPE}",
        addresses=[socket.inet_aton(_local_ip())],
        port=port,
        properties={"node": node_name},
    )
    zc.register_service(info)
    return zc


def browse(timeout: float = 3.0) -> List[str]:
    """
    Return ['ip:port', ...] for every _dhlpe._tcp service seen within
    `timeout` seconds.

    KeyboardInterrupt is caught and swallowed so that browse() returns
    whatever it found before the signal arrived, and the finally block
    always closes the Zeroconf socket. This is the fix for the leak that
    made a second browse() call fail with "address already in use".
    """
    if Zeroconf is None:
        raise RuntimeError("zeroconf is not installed")

    found: List[str] = []
    stop = threading.Event()
    zc = Zeroconf()

    class _L:
        def add_service(self, zc_, type_, name):
            info = zc_.get_service_info(type_, name, timeout=2000)
            if info and info.addresses:
                ip = socket.inet_ntoa(info.addresses[0])
                found.append(f"{ip}:{info.port}")

        def update_service(self, *args):
            pass

        def remove_service(self, *args):
            pass

    ServiceBrowser(zc, SERVICE_TYPE, _L())
    try:
        stop.wait(timeout)
    except KeyboardInterrupt:
        pass
    finally:
        zc.close()
    return found
