from pathlib import Path
import json
import time


BASE_DIR = Path(__file__).resolve().parent

STATE_FILE = (
    BASE_DIR
    / "data"
    / "containment_state.json"
)

VALID_MODES = {
    "NONE",
    "PARTIAL",
    "ISOLATED",
}


def default_containment_state() -> dict:
    return {
        "session_id": None,
        "mode": "NONE",
        "blocked_ips": [],
        "reason": "",
        "updated_ts": time.time(),
    }


def read_containment_state() -> dict:
    if not STATE_FILE.exists():
        return default_containment_state()

    try:
        data = json.loads(
            STATE_FILE.read_text(
                encoding="utf-8"
            )
        )

    except (
        json.JSONDecodeError,
        OSError
    ):
        return default_containment_state()

    if not isinstance(data, dict):
        return default_containment_state()

    state = default_containment_state()
    state.update(data)

    if state.get("mode") not in VALID_MODES:
        state["mode"] = "NONE"

    if not isinstance(
        state.get("blocked_ips"),
        list
    ):
        state["blocked_ips"] = []

    return state


def write_containment_state(
    session_id: int,
    mode: str,
    blocked_ips: list | None = None,
    reason: str = "",
) -> dict:

    if mode not in VALID_MODES:
        raise ValueError(
            f"Modo de contención inválido: {mode}"
        )

    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    payload = {
        "session_id": session_id,
        "mode": mode,
        "blocked_ips": blocked_ips or [],
        "reason": reason,
        "updated_ts": time.time(),
    }

    temporary_file = STATE_FILE.with_suffix(
        ".tmp"
    )

    temporary_file.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )

    temporary_file.replace(
        STATE_FILE
    )

    return payload


def reset_containment_state(
    session_id: int
) -> dict:

    return write_containment_state(
        session_id=session_id,
        mode="NONE",
        blocked_ips=[],
        reason=(
            "Estado de contención reiniciado "
            "al iniciar una nueva sesión."
        ),
    )
