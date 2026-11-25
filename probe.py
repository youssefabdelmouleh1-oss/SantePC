"""
Sonde santé PC — v0 (lecture seule)

Collects structural health signals from a Windows machine, applies simple
transparent rules, and writes:
  - reports/sante_<date>.json  : blind machine state + findings (shareable)
  - reports/sante_<date>.html  : one-page report in French (local)

Principles:
  - Read-only: nothing on the machine is changed.
  - Blind: no user name, machine name, serial number, IP address, Wi-Fi name,
    file names or log message text is collected.
  - Every finding points to a measured value. Missing data is reported as
    "inconnu", never guessed.

Requires: Windows 10/11, Python 3.10+. No third-party packages.
Run from an administrator terminal for disk wear/error counters.
Usage:  python probe.py          (real machine)
        python probe.py --demo   (sample data, any OS, to preview the report)
"""

from __future__ import annotations

import argparse
import ctypes
import html
import json
import os
import platform
import re
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

PROBE_VERSION = "0.1.0"
EVENT_WINDOW_DAYS = 7

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def is_windows() -> bool:
    return platform.system() == "Windows"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def ps_json(body: str, timeout: int = 120):
    """Run a PowerShell block and return its output parsed as a JSON list."""
    script = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$ErrorActionPreference = 'SilentlyContinue'; "
        f"$r = & {{ {body} }}; "
        "ConvertTo-Json -Depth 4 -Compress -InputObject @($r)"
    )
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", script],
        capture_output=True, timeout=timeout,
    )
    out = proc.stdout.decode("utf-8", errors="replace").strip()
    if not out:
        return []
    data = json.loads(out)
    if isinstance(data, dict):
        data = [data]
    return data


def unknown(reason: str) -> dict:
    return {"statut": "inconnu", "raison": reason}


# --------------------------------------------------------------------------
# Collectors (all read-only)
# --------------------------------------------------------------------------

def collect_system() -> dict:
    rows = ps_json(r"""
        $os  = Get-CimInstance Win32_OperatingSystem
        $cs  = Get-CimInstance Win32_ComputerSystem
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        [pscustomobject]@{
            os_caption   = $os.Caption
            os_version   = $os.Version
            os_build     = $os.BuildNumber
            last_boot    = $os.LastBootUpTime.ToUniversalTime().ToString('o')
            manufacturer = $cs.Manufacturer
            model        = $cs.Model
            ram_gb       = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
            free_ram_gb  = [math]::Round(($os.FreePhysicalMemory * 1KB) / 1GB, 1)
            cpu          = $cpu.Name.Trim()
            cores        = $cpu.NumberOfCores
            startup_items = @(Get-CimInstance Win32_StartupCommand).Count
        }
    """)
    if not rows:
        return unknown("informations système illisibles")
    s = rows[0]
    try:
        boot = datetime.fromisoformat(s["last_boot"].replace("Z", "+00:00"))
        s["uptime_days"] = round((datetime.now(timezone.utc) - boot).total_seconds() / 86400, 1)
    except Exception:
        s["uptime_days"] = None
    s.pop("last_boot", None)  # keep only the derived value
    return s


def collect_disks() -> list | dict:
    rows = ps_json(r"""
        Get-PhysicalDisk | ForEach-Object {
            $r = $null
            try { $r = $_ | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}
            [pscustomobject]@{
                model          = $_.FriendlyName
                media          = [string]$_.MediaType
                bus            = [string]$_.BusType
                size_gb        = [math]::Round($_.Size / 1GB, 0)
                health         = [string]$_.HealthStatus
                wear_pct       = $r.Wear
                temperature_c  = $r.Temperature
                read_errors    = $r.ReadErrorsTotal
                write_errors   = $r.WriteErrorsTotal
                power_on_hours = $r.PowerOnHours
            }
        }
    """)
    if not rows:
        return unknown("aucun disque lisible")
    return rows


def collect_volumes() -> list | dict:
    rows = ps_json(r"""
        Get-Volume | Where-Object { $_.DriveLetter -and [string]$_.DriveType -eq 'Fixed' } |
        ForEach-Object {
            [pscustomobject]@{
                letter  = [string]$_.DriveLetter
                size_gb = [math]::Round($_.Size / 1GB, 1)
                free_gb = [math]::Round($_.SizeRemaining / 1GB, 1)
            }
        }
    """)
    if not rows:
        return unknown("aucun volume lisible")
    return rows


def collect_battery() -> dict:
    out_path = Path(tempfile.gettempdir()) / f"battery_{uuid.uuid4().hex}.xml"
    try:
        subprocess.run(["powercfg", "/batteryreport", "/xml", "/output", str(out_path)],
                       capture_output=True, timeout=60)
        if not out_path.exists():
            return unknown("rapport batterie indisponible")
        root = ET.parse(out_path).getroot()
    except Exception as e:
        return unknown(f"rapport batterie illisible ({type(e).__name__})")
    finally:
        try:
            out_path.unlink()
        except Exception:
            pass

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    batteries = []
    for el in root.iter():
        if local(el.tag) != "Battery":
            continue
        vals = {local(c.tag): (c.text or "").strip() for c in el}
        try:
            design = int(vals.get("DesignCapacity", "0"))
            full = int(vals.get("FullChargeCapacity", "0"))
        except ValueError:
            continue
        cycles = vals.get("CycleCount")
        batteries.append({
            "design_mwh": design,
            "full_charge_mwh": full,
            "health_pct": round(100 * full / design, 1) if design > 0 else None,
            "cycles": int(cycles) if cycles and cycles.isdigit() else None,
        })
    if not batteries:
        return {"statut": "absente"}
    return {"statut": "presente", "batteries": batteries}


def collect_events() -> list | dict:
    # Only provider names, event IDs and counts. Never the message text.
    rows = ps_json(rf"""
        $since = (Get-Date).AddDays(-{EVENT_WINDOW_DAYS})
        $ev = @(Get-WinEvent -FilterHashtable @{{LogName='System'; Level=1,2; StartTime=$since}})
        foreach ($p in 'Microsoft-Windows-WHEA-Logger','disk','Ntfs','Microsoft-Windows-Ntfs') {{
            $ev += @(Get-WinEvent -FilterHashtable @{{LogName='System'; ProviderName=$p; Level=3; StartTime=$since}})
        }}
        $ev | Where-Object {{ $_ }} | Group-Object ProviderName, Id | ForEach-Object {{
            [pscustomobject]@{{
                provider = $_.Group[0].ProviderName
                id       = $_.Group[0].Id
                level    = $_.Group[0].Level
                count    = $_.Count
            }}
        }}
    """)
    return rows  # empty list = no error events, which is good news


def collect_devices() -> list | dict:
    # Device class + error code only: device names can contain personal names.
    rows = ps_json(r"""
        Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 } |
        ForEach-Object {
            [pscustomobject]@{
                class        = [string]$_.PNPClass
                manufacturer = [string]$_.Manufacturer
                error_code   = $_.ConfigManagerErrorCode
            }
        }
    """)
    return rows


def collect_updates() -> dict:
    rows = ps_json(r"""
        $last = $null
        try {
            $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
            $n = $s.GetTotalHistoryCount()
            if ($n -gt 0) {
                $h = $s.QueryHistory(0, [math]::Min($n, 100)) |
                     Where-Object { $_.ResultCode -eq 2 } |
                     Sort-Object Date -Descending | Select-Object -First 1
                if ($h) { $last = $h.Date.ToUniversalTime().ToString('o') }
            }
        } catch {}
        $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
                   (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        [pscustomobject]@{ last_update = $last; reboot_pending = [bool]$pending }
    """)
    if not rows:
        return unknown("historique des mises à jour illisible")
    u = rows[0]
    try:
        last = datetime.fromisoformat(u["last_update"].replace("Z", "+00:00"))
        u["days_since_update"] = (datetime.now(timezone.utc) - last).days
    except Exception:
        u["days_since_update"] = None
    u.pop("last_update", None)
    return u


def _tcp_latency(host: str, port: int = 443, n: int = 8, timeout: float = 2.0) -> dict:
    times, fails = [], 0
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                times.append((time.perf_counter() - t0) * 1000)
        except OSError:
            fails += 1
        time.sleep(0.1)
    return {
        "median_ms": round(statistics.median(times), 1) if times else None,
        "loss_pct": round(100 * fails / n, 1),
    }


def collect_network() -> dict:
    net: dict = {}
    # Latency: TCP connections to two public anycast resolvers (no admin needed,
    # independent of the Windows display language).
    a = _tcp_latency("1.1.1.1")
    b = _tcp_latency("8.8.8.8")
    meds = [x["median_ms"] for x in (a, b) if x["median_ms"] is not None]
    net["latency_ms"] = round(min(meds), 1) if meds else None
    net["loss_pct"] = round((a["loss_pct"] + b["loss_pct"]) / 2, 1)

    # DNS resolution time
    dns = []
    for name in ("www.wikipedia.org", "www.cloudflare.com", "www.service-public.fr"):
        t0 = time.perf_counter()
        try:
            socket.getaddrinfo(name, 443)
            dns.append((time.perf_counter() - t0) * 1000)
        except OSError:
            pass
    net["dns_ms"] = round(statistics.median(dns), 1) if dns else None
    net["dns_failures"] = 3 - len(dns)

    # Wi-Fi signal only (the network name is read but never kept)
    if is_windows():
        try:
            out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                 capture_output=True, timeout=20).stdout
            text = out.decode("mbcs", errors="ignore") if hasattr(out, "decode") else ""
            m = re.search(r"Signal\s*:\s*(\d+)\s*%", text)
            net["wifi_signal_pct"] = int(m.group(1)) if m else None
        except Exception:
            net["wifi_signal_pct"] = None
    return net


COLLECTORS = {
    "systeme": collect_system,
    "disques": collect_disks,
    "volumes": collect_volumes,
    "batterie": collect_battery,
    "evenements": collect_events,
    "peripheriques": collect_devices,
    "mises_a_jour": collect_updates,
    "reseau": collect_network,
}


def collect_all() -> dict:
    state = {}
    for name, fn in COLLECTORS.items():
        try:
            state[name] = fn()
        except Exception as e:
            state[name] = unknown(f"erreur de collecte ({type(e).__name__})")
    return state


# --------------------------------------------------------------------------
# Rules: every finding carries the measured value it is based on.
# Thresholds are v0 guesses, to be tuned with real machines.
# --------------------------------------------------------------------------

@dataclass
class Finding:
    domaine: str
    niveau: str        # "agir", "surveiller", "ok", "inconnu"
    titre: str
    preuve: str        # the measured value behind the finding
    conseil: str = ""


SEVERITY_ORDER = {"agir": 0, "surveiller": 1, "inconnu": 2, "ok": 3}

KNOWN_EVENTS = {
    ("Microsoft-Windows-Kernel-Power", 41): ("surveiller", "Arrêts brutaux (coupure ou plantage)",
        "Vérifier l'alimentation, la batterie et les plantages récents."),
    ("Microsoft-Windows-WER-SystemErrorReporting", 1001): ("surveiller", "Écrans bleus (BugCheck)",
        "Noter la fréquence ; souvent lié à un pilote ou à la mémoire."),
    ("Microsoft-Windows-WHEA-Logger", None): ("surveiller", "Erreurs matérielles signalées par le processeur ou le bus",
        "À surveiller : peut annoncer un composant fatigué."),
    ("disk", 7): ("agir", "Blocs défectueux sur un disque",
        "Sauvegarder maintenant, puis contrôler le disque."),
    ("disk", 51): ("surveiller", "Erreurs d'écriture/pagination sur un disque",
        "Sauvegarder et surveiller l'évolution."),
    ("disk", 153): ("surveiller", "Opérations disque relancées",
        "Signe possible de disque ou câble fatigué."),
    ("Ntfs", 55): ("agir", "Corruption du système de fichiers",
        "Sauvegarder, puis planifier une vérification du disque."),
    ("Microsoft-Windows-Ntfs", 55): ("agir", "Corruption du système de fichiers",
        "Sauvegarder, puis planifier une vérification du disque."),
    ("Ntfs", 98): ("surveiller", "Volume à vérifier",
        "Planifier une vérification du disque."),
    ("Microsoft-Windows-Ntfs", 98): ("surveiller", "Volume à vérifier",
        "Planifier une vérification du disque."),
}


def is_unknown(x) -> bool:
    return isinstance(x, dict) and x.get("statut") == "inconnu"


def evaluate(state: dict) -> list[Finding]:
    f: list[Finding] = []

    for domain, value in state.items():
        if is_unknown(value):
            f.append(Finding(domain, "inconnu", "Donnée non disponible", value.get("raison", "")))

    # Disks
    disks = state.get("disques")
    if isinstance(disks, list):
        for d in disks:
            name = f"{d.get('model') or 'Disque'} ({d.get('media')}, {d.get('size_gb')} Go)"
            health = d.get("health")
            if health and health != "Healthy":
                f.append(Finding("disques", "agir", f"{name} : état signalé « {health} »",
                                 f"HealthStatus = {health}", "Sauvegarder maintenant."))
            wear = d.get("wear_pct")
            if wear is not None:
                if wear >= 80:
                    f.append(Finding("disques", "agir", f"{name} : usure élevée",
                                     f"usure = {wear} %", "Sauvegarder et prévoir le remplacement."))
                elif wear >= 50:
                    f.append(Finding("disques", "surveiller", f"{name} : usure à mi-vie",
                                     f"usure = {wear} %", "Suivre l'évolution chaque mois."))
                else:
                    f.append(Finding("disques", "ok", f"{name} : usure faible", f"usure = {wear} %"))
            elif not is_admin():
                f.append(Finding("disques", "inconnu", f"{name} : usure non lue",
                                 "compteurs réservés à l'administrateur",
                                 "Relancer la sonde dans un terminal administrateur."))
            errs = (d.get("read_errors") or 0) + (d.get("write_errors") or 0)
            if errs > 0:
                f.append(Finding("disques", "surveiller", f"{name} : erreurs de lecture/écriture",
                                 f"erreurs = {errs}", "Surveiller ; sauvegarder si ça augmente."))
            temp = d.get("temperature_c")
            if temp and temp >= 70:
                f.append(Finding("disques", "surveiller", f"{name} : température élevée",
                                 f"température = {temp} °C", "Vérifier la ventilation."))

    # Volumes
    vols = state.get("volumes")
    if isinstance(vols, list):
        for v in vols:
            size, free = v.get("size_gb") or 0, v.get("free_gb") or 0
            if size <= 0:
                continue
            pct = round(100 * free / size, 1)
            ev = f"espace libre = {free} Go sur {size} Go ({pct} %)"
            if pct < 10:
                f.append(Finding("volumes", "agir", f"Lecteur {v.get('letter')}: presque plein", ev,
                                 "Libérer de l'espace : le système ralentit et les mises à jour échouent."))
            elif pct < 20:
                f.append(Finding("volumes", "surveiller", f"Lecteur {v.get('letter')}: espace limité", ev))
            else:
                f.append(Finding("volumes", "ok", f"Lecteur {v.get('letter')}: espace suffisant", ev))

    # Battery
    bat = state.get("batterie")
    if isinstance(bat, dict) and bat.get("statut") == "presente":
        for i, b in enumerate(bat["batteries"], 1):
            h = b.get("health_pct")
            if h is None:
                continue
            ev = f"capacité = {h} % de l'origine" + (f", {b['cycles']} cycles" if b.get("cycles") else "")
            if h < 60:
                f.append(Finding("batterie", "agir", f"Batterie {i} : très usée", ev,
                                 "Prévoir le remplacement de la batterie."))
            elif h < 80:
                f.append(Finding("batterie", "surveiller", f"Batterie {i} : usure notable", ev))
            else:
                f.append(Finding("batterie", "ok", f"Batterie {i} : en bon état", ev))

    # Events
    events = state.get("evenements")
    if isinstance(events, list):
        matched = 0
        for e in events:
            key = (e.get("provider"), e.get("id"))
            rule = KNOWN_EVENTS.get(key) or KNOWN_EVENTS.get((e.get("provider"), None))
            if rule:
                matched += 1
                lvl, title, advice = rule
                f.append(Finding("evenements", lvl, title,
                                 f"{e.get('count')} fois en {EVENT_WINDOW_DAYS} jours "
                                 f"({e.get('provider')}, ID {e.get('id')})", advice))
        total = sum(e.get("count", 0) for e in events)
        if matched == 0:
            f.append(Finding("evenements", "ok", "Aucun événement critique connu",
                             f"{total} erreurs système diverses en {EVENT_WINDOW_DAYS} jours"))

    # Devices
    devs = state.get("peripheriques")
    if isinstance(devs, list):
        if devs:
            for d in devs:
                f.append(Finding("peripheriques", "surveiller",
                                 f"Périphérique en erreur ({d.get('class') or 'classe inconnue'})",
                                 f"code d'erreur {d.get('error_code')}"
                                 + (f", fabricant {d['manufacturer']}" if d.get("manufacturer") else ""),
                                 "Vérifier ou réinstaller le pilote."))
        else:
            f.append(Finding("peripheriques", "ok", "Aucun périphérique en erreur", "0 périphérique en erreur"))

    # Updates
    upd = state.get("mises_a_jour")
    if isinstance(upd, dict) and not is_unknown(upd):
        days = upd.get("days_since_update")
        if days is not None:
            if days > 45:
                f.append(Finding("mises_a_jour", "surveiller", "Mises à jour en retard",
                                 f"dernière mise à jour réussie il y a {days} jours",
                                 "Lancer Windows Update."))
            else:
                f.append(Finding("mises_a_jour", "ok", "Mises à jour récentes",
                                 f"dernière mise à jour réussie il y a {days} jours"))
        if upd.get("reboot_pending"):
            f.append(Finding("mises_a_jour", "surveiller", "Redémarrage en attente",
                             "Windows signale un redémarrage requis",
                             "Redémarrer pour terminer l'installation."))

    # System
    sysi = state.get("systeme")
    if isinstance(sysi, dict) and not is_unknown(sysi):
        up = sysi.get("uptime_days")
        if up is not None and up > 14:
            f.append(Finding("systeme", "surveiller", "Pas de redémarrage depuis longtemps",
                             f"allumé depuis {up} jours",
                             "Redémarrer de temps en temps évite bien des lenteurs."))
        st = sysi.get("startup_items")
        if st is not None and st > 15:
            f.append(Finding("systeme", "surveiller", "Beaucoup de programmes au démarrage",
                             f"{st} programmes au démarrage", "Désactiver ceux qui ne servent pas."))
        ram, free = sysi.get("ram_gb"), sysi.get("free_ram_gb")
        if ram and free is not None and free / ram < 0.1:
            f.append(Finding("systeme", "surveiller", "Mémoire presque saturée",
                             f"{free} Go libres sur {ram} Go au moment du test"))

    # Network
    net = state.get("reseau")
    if isinstance(net, dict) and not is_unknown(net):
        lat, loss = net.get("latency_ms"), net.get("loss_pct", 0)
        if lat is None:
            f.append(Finding("reseau", "agir", "Internet injoignable",
                             "aucune connexion de test n'a abouti", "Vérifier la connexion."))
        else:
            ev = f"latence = {lat} ms, échecs = {loss} %"
            if loss >= 20:
                f.append(Finding("reseau", "agir", "Connexion instable", ev))
            elif lat > 100 or loss > 0:
                f.append(Finding("reseau", "surveiller", "Connexion lente ou irrégulière", ev))
            else:
                f.append(Finding("reseau", "ok", "Connexion correcte", ev))
        dns = net.get("dns_ms")
        if dns is not None and dns > 300:
            f.append(Finding("reseau", "surveiller", "Résolution DNS lente", f"DNS = {dns} ms"))
        sig = net.get("wifi_signal_pct")
        if sig is not None and sig < 40:
            f.append(Finding("reseau", "surveiller", "Signal Wi-Fi faible", f"signal = {sig} %",
                             "Se rapprocher de la borne ou vérifier le point d'accès."))

    f.sort(key=lambda x: (SEVERITY_ORDER.get(x.niveau, 9), x.domaine))
    return f


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

LEVEL_LABEL = {"agir": "À traiter", "surveiller": "À surveiller", "inconnu": "Inconnu", "ok": "OK"}
LEVEL_COLOR = {"agir": "#b42318", "surveiller": "#b54708", "inconnu": "#667085", "ok": "#027a48"}


def render_html(state: dict, findings: list[Finding], meta: dict) -> str:
    counts = {k: sum(1 for x in findings if x.niveau == k) for k in LEVEL_LABEL}
    rows = []
    for x in findings:
        rows.append(
            f"<tr><td><span class='tag' style='background:{LEVEL_COLOR[x.niveau]}'>"
            f"{LEVEL_LABEL[x.niveau]}</span></td>"
            f"<td><b>{html.escape(x.titre)}</b><div class='ev'>{html.escape(x.preuve)}</div></td>"
            f"<td>{html.escape(x.conseil)}</td></tr>"
        )
    sysi = state.get("systeme") if isinstance(state.get("systeme"), dict) else {}
    machine = " · ".join(str(v) for v in [
        sysi.get("manufacturer"), sysi.get("model"), sysi.get("cpu"),
        f"{sysi.get('ram_gb')} Go RAM" if sysi.get("ram_gb") else None,
        sysi.get("os_caption"),
    ] if v)
    summary = " · ".join(f"{counts[k]} {LEVEL_LABEL[k].lower()}" for k in ("agir", "surveiller", "inconnu", "ok"))
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><title>Bilan de santé du PC</title>
<style>
body{{font-family:system-ui,Segoe UI,sans-serif;max-width:880px;margin:32px auto;padding:0 16px;color:#1d2939}}
h1{{font-size:22px;margin-bottom:4px}} .sub{{color:#667085;font-size:14px}}
table{{border-collapse:collapse;width:100%;margin-top:20px}}
td{{border-top:1px solid #eaecf0;padding:10px 8px;vertical-align:top;font-size:14px}}
.tag{{color:#fff;border-radius:6px;padding:2px 8px;font-size:12px;white-space:nowrap}}
.ev{{color:#475467;font-size:13px;margin-top:2px}}
.box{{background:#f9fafb;border:1px solid #eaecf0;border-radius:8px;padding:12px 16px;margin-top:24px;font-size:13px;color:#475467}}
</style></head><body>
<h1>Bilan de santé du PC</h1>
<div class="sub">{html.escape(machine)}</div>
<div class="sub">{html.escape(meta['date_locale'])} · sonde v{PROBE_VERSION} · {html.escape(summary)}</div>
<table>{''.join(rows)}</table>
<div class="box"><b>Ce que la sonde a lu :</b> état et usure des disques, espace libre, santé de la batterie,
codes d'erreur système des {EVENT_WINDOW_DAYS} derniers jours (sans leur texte), périphériques en erreur,
date de la dernière mise à jour, latence réseau et signal Wi-Fi.<br>
<b>Ce qu'elle ne lit jamais :</b> nom d'utilisateur, nom du poste, numéros de série, adresses IP,
nom du réseau Wi-Fi, fichiers, historique, contenu des journaux.<br>
<b>Aucune modification</b> n'a été faite sur la machine.
{'' if meta['admin'] else '<br><b>Note :</b> lancée sans droits administrateur, certaines données disque manquent.'}
</div></body></html>"""


def write_outputs(state: dict, findings: list[Finding], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now()
    meta = {
        "probe_version": PROBE_VERSION,
        "run_id": uuid.uuid4().hex[:12],  # random per run: not tied to the machine
        "date_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ"),
        "date_locale": now.strftime("%d/%m/%Y %H:%M"),
        "admin": is_admin(),
    }
    stamp = now.strftime("%Y%m%d_%H%M")
    jpath = out_dir / f"sante_{stamp}.json"
    hpath = out_dir / f"sante_{stamp}.html"
    jpath.write_text(json.dumps(
        {"meta": {k: v for k, v in meta.items() if k != "date_locale"},
         "etat": state,
         "constats": [asdict(x) for x in findings]},
        ensure_ascii=False, indent=2), encoding="utf-8")
    hpath.write_text(render_html(state, findings, meta), encoding="utf-8")
    return jpath, hpath


# --------------------------------------------------------------------------
# Demo data (to preview the report on any OS)
# --------------------------------------------------------------------------

DEMO_STATE = {
    "systeme": {"os_caption": "Microsoft Windows 11 Famille", "os_version": "10.0.26100",
                "os_build": "26100", "manufacturer": "Micro-Star International Co., Ltd.",
                "model": "Exemple 15", "ram_gb": 15.3, "free_ram_gb": 6.2,
                "cpu": "AMD Ryzen 5 7535HS", "cores": 6, "startup_items": 19, "uptime_days": 21.4},
    "disques": [{"model": "NVMe SSD 512GB", "media": "SSD", "bus": "NVMe", "size_gb": 477,
                 "health": "Healthy", "wear_pct": 57, "temperature_c": 44,
                 "read_errors": 0, "write_errors": 0, "power_on_hours": 3120}],
    "volumes": [{"letter": "C", "size_gb": 476.1, "free_gb": 38.5}],
    "batterie": {"statut": "presente", "batteries": [
        {"design_mwh": 53500, "full_charge_mwh": 39100, "health_pct": 73.1, "cycles": 412}]},
    "evenements": [{"provider": "Microsoft-Windows-Kernel-Power", "id": 41, "level": 1, "count": 2},
                   {"provider": "Microsoft-Windows-DistributedCOM", "id": 10016, "level": 2, "count": 37}],
    "peripheriques": [],
    "mises_a_jour": {"reboot_pending": True, "days_since_update": 12},
    "reseau": {"latency_ms": 18.4, "loss_pct": 0.0, "dns_ms": 42.0, "dns_failures": 0,
               "wifi_signal_pct": 34},
}


def main() -> int:
    ap = argparse.ArgumentParser(description="Sonde santé PC v0 (lecture seule)")
    ap.add_argument("--demo", action="store_true", help="use sample data instead of this machine")
    ap.add_argument("--out", default="reports", help="output folder (default: reports)")
    args = ap.parse_args()

    if args.demo:
        state = DEMO_STATE
    else:
        if not is_windows():
            print("Cette sonde fonctionne sous Windows. Utilisez --demo pour un aperçu.")
            return 1
        if not is_admin():
            print("Note : sans droits administrateur, l'usure des disques ne sera pas lue.")
        print("Collecte en cours (environ 30 s)…")
        state = collect_all()

    findings = evaluate(state)
    jpath, hpath = write_outputs(state, findings, Path(args.out))
    n_act = sum(1 for x in findings if x.niveau == "agir")
    n_watch = sum(1 for x in findings if x.niveau == "surveiller")
    print(f"Terminé : {n_act} à traiter, {n_watch} à surveiller.")
    print(f"Rapport : {hpath.resolve()}")
    print(f"Données anonymes : {jpath.resolve()}")
    if not args.demo and is_windows():
        try:
            os.startfile(hpath.resolve())  # type: ignore[attr-defined]
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
