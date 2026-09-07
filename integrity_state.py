from pathlib import Path
import json
import time


BASE_DIR = Path(__file__).resolve().parent

STATE_FILE = (
    BASE_DIR
    / "data"
    / "integrity_state.json"
)

VALID_MODES = {
    "NONE",
    "PROTECTED",
    "ISOLATED",
}


def default_integrity_state() -> dict:
    return {
        "session_id": None,
        "mode": "NONE",
        "reason": "",
        "updated_ts": time.time(),
    }


def read_integrity_state() -> dict:

    if not STATE_FILE.exists():
        return default_integrity_state()

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
        return default_integrity_state()

    if not isinstance(data, dict):
        return default_integrity_state()

    state = default_integrity_state()
    state.update(data)

    if state.get("mode") not in VALID_MODES:
        state["mode"] = "NONE"

    return state


def write_integrity_state(
    session_id: int,
    mode: str,
    reason: str = "",
) -> dict:

    if mode not in VALID_MODES:
        raise ValueError(
            f"Modo de integridad inválido: {mode}"
        )

    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    payload = {
        "session_id": session_id,
        "mode": mode,
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


def reset_integrity_state(
    session_id: int
) -> dict:

    return write_integrity_state(
        session_id=session_id,
        mode="NONE",
        reason=(
            "Estado de integridad reiniciado "
            "al iniciar una nueva sesión CR-002."
        ),
    )

