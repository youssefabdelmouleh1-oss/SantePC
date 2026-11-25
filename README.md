# Probe v0 — read-only PC health check

One Python file, no dependencies. It reads the machine's health signals, applies simple rules, and writes a one-page report in French. It changes nothing on the machine.

## Run it (Windows 10/11, Python 3.10+)

1. Put `probe.py` in a folder.
2. Open a terminal **as administrator** (needed for disk wear and error counters).
3. `cd` into the folder and run:

```
python probe.py
```

It takes about 30 seconds, then opens the HTML report. Output goes to `reports/`:

- `sante_<date>.html`: the report for the person in front of the machine
- `sante_<date>.json`: the anonymous machine state + findings (this is what we collect during the trial)

To preview the report without a Windows machine: `python probe.py --demo`

## What it reads

| Area | Signals |
| --- | --- |
| Disks | health status, wear %, temperature, read/write errors, power-on hours |
| Volumes | free space per fixed drive |
| Battery | design vs current capacity, cycle count (`powercfg /batteryreport`) |
| Events | System log critical/error events from the last 7 days: provider + ID + count only |
| Devices | devices in error: class, manufacturer, error code |
| Updates | days since last successful Windows Update, pending reboot |
| System | OS version, model, CPU, RAM, uptime, number of startup programs |
| Network | TCP latency and failures to 1.1.1.1 / 8.8.8.8, DNS time, Wi-Fi signal % |

## What it never reads or stores

User name, computer name, serial numbers, IP addresses, Wi-Fi network name, device names, file names, browsing history, event message text. The `run_id` is random for each run and isn't tied to the machine.

## Rules

Every finding carries the measured value it's based on (`preuve`). Missing data is shown as `inconnu`, never guessed. The thresholds are v0 guesses (e.g. disk wear ≥ 50 % = watch, ≥ 80 % = act; free space < 10 % = act; battery < 80 % = watch, < 60 % = act). We'll tune them with the trial data.

## Known limits of v0

- Not yet tested on a real Windows machine.
- Disk counters depend on the drive and driver. Some NVMe drives report no wear value.
- Latency is measured with TCP connections, not ping, so it works without admin rights and on any Windows language.
