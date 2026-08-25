from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import os
import platform
import shutil
import sys


def _safe_percent(value):
    try:
        return round(float(value), 1)
    except Exception:
        return None


def _disk_info():
    try:
        usage = shutil.disk_usage("/")

        total = int(usage.total)
        used = int(usage.used)
        free = int(usage.free)

        percent = (
            round((used / total) * 100, 1)
            if total
            else 0.0
        )

        return {
            "total": total,
            "used": used,
            "free": free,
            "percent": percent,
        }

    except Exception:
        return {
            "total": 0,
            "used": 0,
            "free": 0,
            "percent": None,
        }


def _memory_info():
    try:
        import psutil

        vm = psutil.virtual_memory()

        return {
            "total": int(vm.total),
            "used": int(vm.used),
            "available": int(vm.available),
            "percent": _safe_percent(vm.percent),
        }

    except Exception:
        return {
            "total": 0,
            "used": 0,
            "available": 0,
            "percent": None,
        }


def _cpu_info():
    try:
        import psutil

        percent = psutil.cpu_percent(interval=0.05)
        count = psutil.cpu_count()

        return {
            "percent": _safe_percent(percent),
            "count": count or os.cpu_count() or 0,
        }

    except Exception:
        return {
            "percent": None,
            "count": os.cpu_count() or 0,
        }


def _process_info():
    try:
        import psutil

        proc = psutil.Process()

        return {
            "pid": proc.pid,
            "memory_percent": round(
                proc.memory_percent(),
                2,
            ),
            "threads": proc.num_threads(),
        }

    except Exception:
        return {
            "pid": os.getpid(),
            "memory_percent": None,
            "threads": None,
        }


def _bytes_label(value):
    try:
        value = float(value)
    except Exception:
        return "N/A"

    units = ["B", "KB", "MB", "GB", "TB"]
    unit = units[0]

    for candidate in units:
        unit = candidate

        if value < 1024 or candidate == units[-1]:
            break

        value /= 1024

    return f"{value:.1f} {unit}"


def get_system_center_data():
    disk = _disk_info()
    memory = _memory_info()
    cpu = _cpu_info()
    process = _process_info()

    root = Path(".").resolve()

    status = "ONLINE"

    warnings = []

    if (
        memory["percent"] is not None
        and memory["percent"] >= 90
    ):
        warnings.append("Bellek kullanımı kritik seviyeye yaklaştı.")

    if (
        disk["percent"] is not None
        and disk["percent"] >= 90
    ):
        warnings.append("Disk kullanımı kritik seviyeye yaklaştı.")

    if (
        cpu["percent"] is not None
        and cpu["percent"] >= 95
    ):
        warnings.append("CPU kullanımı kritik seviyede.")

    health = "HEALTHY" if not warnings else "WARNING"

    return {
        "status": status,
        "health": health,

        "platform": platform.system() or "Unknown",
        "release": platform.release() or "Unknown",
        "machine": platform.machine() or "Unknown",
        "python_version": platform.python_version(),

        "cpu": cpu,
        "memory": memory,
        "disk": disk,
        "process": process,

        "cpu_percent": cpu["percent"],
        "cpu_count": cpu["count"],

        "memory_percent": memory["percent"],
        "memory_total_label": _bytes_label(memory["total"]),
        "memory_used_label": _bytes_label(memory["used"]),
        "memory_available_label": _bytes_label(
            memory["available"]
        ),

        "disk_percent": disk["percent"],
        "disk_total_label": _bytes_label(disk["total"]),
        "disk_used_label": _bytes_label(disk["used"]),
        "disk_free_label": _bytes_label(disk["free"]),

        "process_pid": process["pid"],
        "process_memory_percent": process["memory_percent"],
        "process_threads": process["threads"],

        "project_root": str(root),
        "python_executable": sys.executable,

        "warnings": warnings,
        "warning_count": len(warnings),

        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }
