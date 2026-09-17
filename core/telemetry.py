from pathlib import Path
from datetime import datetime, timezone, timedelta
import json


BASE_DIR = Path(__file__).resolve().parents[1]

LOG_FILE = (
    BASE_DIR
    / "target_app"
    / "logs"
    / "events.jsonl"
)


def read_events(limit: int = 50) -> list[dict]:
    """
    Lee los últimos eventos generados por
    el servicio objetivo del Cyber Range.
    """

    if not LOG_FILE.exists():
        return []

    events = []

    with LOG_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
                events.append(event)

            except json.JSONDecodeError:
                # Ignorar líneas corruptas sin
                # detener el motor de simulación.
                continue

    return events[-limit:]


def analyze_authentication(
    window_minutes: int = 5,
    failure_threshold: int = 3
) -> dict:
    """
    Analiza actividad de autenticación reciente.

    Genera un estado de alerta cuando el número
    de autenticaciones fallidas alcanza el umbral
    configurado dentro de una ventana temporal.
    """

    events = read_events(limit=200)

    now = datetime.now(timezone.utc)

    window_start = (
        now - timedelta(minutes=window_minutes)
    )

    recent_events = []

    for event in events:

        timestamp_text = event.get("timestamp")

        if not timestamp_text:
            continue

        try:
            timestamp = datetime.fromisoformat(
                timestamp_text
            )

        except ValueError:
            continue

        if timestamp >= window_start:
            recent_events.append(event)

    login_failures = [
        event
        for event in recent_events
        if event.get("event_type") == "LOGIN_FAILURE"
    ]

    login_successes = [
        event
        for event in recent_events
        if event.get("event_type") == "LOGIN_SUCCESS"
    ]

    alert = len(login_failures) >= failure_threshold

    if alert:
        status = "ALERT"
        message = (
            "Se detectó un patrón anómalo de "
            "autenticaciones fallidas."
        )

    else:
        status = "NORMAL"
        message = (
            "No se supera el umbral de "
            "autenticaciones fallidas."
        )

    return {
        "status": status,
        "message": message,
        "window_minutes": window_minutes,
        "failure_threshold": failure_threshold,
        "login_failures": len(login_failures),
        "login_successes": len(login_successes),
        "events_analyzed": len(recent_events),
        "recent_events": recent_events
    }
def analyze_compromise(
    window_minutes: int = 10
) -> dict:
    """
    Analiza eventos recientes del servicio objetivo
    para identificar compromisos confirmados.

    En esta versión, un evento AUTH_BYPASS indica
    que la autenticación fue evadida dentro del
    entorno experimental CyberRangeCore.
    """

    events = read_events(limit=200)

    now = datetime.now(timezone.utc)

    window_start = (
        now - timedelta(minutes=window_minutes)
    )

    recent_events = []

    for event in events:

        timestamp_text = event.get("timestamp")

        if not timestamp_text:
            continue

        try:
            timestamp = datetime.fromisoformat(
                timestamp_text
            )

        except ValueError:
            continue

        if timestamp >= window_start:
            recent_events.append(event)

    compromise_events = [
        event
        for event in recent_events
        if event.get("event_type") == "AUTH_BYPASS"
    ]

    compromised = len(compromise_events) > 0

    latest_compromise = None

    if compromised:

        latest_compromise = compromise_events[-1]

        status = "COMPROMISED"

        message = (
            "Se detectó evidencia de acceso no autorizado "
            "mediante evasión del mecanismo de autenticación."
        )

    else:

        status = "NORMAL"

        message = (
            "No se detectaron eventos de compromiso "
            "dentro de la ventana analizada."
        )

    return {
        "status": status,
        "message": message,
        "window_minutes": window_minutes,
        "compromise_count": len(compromise_events),
        "events_analyzed": len(recent_events),
        "latest_compromise": latest_compromise,
        "compromise_events": compromise_events,
        "recent_events": recent_events
    }
def analyze_data_integrity(
    window_minutes: int = 10
) -> dict:

    from datetime import (
        datetime,
        timezone,
        timedelta
    )

    events = read_events(
        limit=200
    )

    current_time = datetime.now(
        timezone.utc
    )

    cutoff = current_time - timedelta(
        minutes=window_minutes
    )

    recent_events = []

    for event in events:

        timestamp_raw = event.get(
            "timestamp"
        )

        if not timestamp_raw:
            continue

        try:
            event_time = datetime.fromisoformat(
                str(timestamp_raw).replace(
                    "Z",
                    "+00:00"
                )
            )

        except ValueError:
            continue

        if event_time.tzinfo is None:
            event_time = event_time.replace(
                tzinfo=timezone.utc
            )

        if event_time >= cutoff:
            recent_events.append(
                event
            )

    tampering_events = [
        event
        for event in recent_events
        if event.get("event_type")
        == "DATA_TAMPERING"
    ]

    if tampering_events:

        status = "TAMPERED"

        message = (
            "Se detectó modificación no autorizada "
            "de información académica."
        )

    else:

        status = "CLEAN"

        message = (
            "No se detectaron modificaciones "
            "no autorizadas en la ventana analizada."
        )

    return {
        "status": status,
        "message": message,
        "window_minutes": window_minutes,
        "tampering_count": len(
            tampering_events
        ),
        "events_analyzed": len(
            recent_events
        ),
        "latest_tampering": (
            tampering_events[-1]
            if tampering_events
            else None
        ),
        "tampering_events": tampering_events,
        "recent_events": recent_events,
    }


# ==========================================================
# REGISTRO EXTENSIBLE DE DETECTORES
# ==========================================================

def _run_authentication_detector(
    config: dict
) -> dict:

    return analyze_authentication(
        window_minutes=int(
            config.get(
                "window_minutes",
                5
            )
        ),
        failure_threshold=int(
            config.get(
                "failure_threshold",
                3
            )
        )
    )


def _run_compromise_detector(
    config: dict
) -> dict:

    return analyze_compromise(
        window_minutes=int(
            config.get(
                "window_minutes",
                10
            )
        )
    )


def _run_data_integrity_detector(
    config: dict
) -> dict:

    return analyze_data_integrity(
        window_minutes=int(
            config.get(
                "window_minutes",
                10
            )
        )
    )


DETECTOR_HANDLERS = {
    "AUTHENTICATION": (
        _run_authentication_detector
    ),
    "COMPROMISE": (
        _run_compromise_detector
    ),
    "DATA_INTEGRITY": (
        _run_data_integrity_detector
    ),
}


SUPPORTED_TELEMETRY_DETECTORS = frozenset(
    DETECTOR_HANDLERS.keys()
)


def run_detector(
    detector_name: str,
    config: dict
) -> dict | None:
    """
    Ejecuta un detector registrado sin que el
    motor principal necesite conocer su
    implementación concreta.

    Retorna None si el detector no está
    registrado.
    """

    handler = DETECTOR_HANDLERS.get(
        detector_name
    )

    if not handler:
        return None

    return handler(
        config
    )
