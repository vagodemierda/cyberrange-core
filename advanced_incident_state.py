import json

from pathlib import Path
from typing import Any


BASE_DIR = Path(
    __file__
).resolve().parent

STATE_FILE = (
    BASE_DIR
    / "data"
    / "advanced_incident_state.json"
)


VALID_STAGES = {
    "INITIAL",
    "ACCOUNT_COMPROMISED",
    "EXFILTRATING",
    "RANSOMWARE_ACTIVE",
    "CONTAINED",
    "RECOVERING",
    "RECOVERED",
}


VALID_RECOVERY_STATES = {
    "NONE",
    "PENDING",
    "BACKUP_RESTORED",
    "SERVICE_REBUILT",
    "ISOLATED",
}


def default_advanced_incident_state(
    session_id: int | None = None
) -> dict[str, Any]:

    return {
        "session_id": session_id,
        "stage": "INITIAL",

        # ----------------------------------------------
        # COMPROMISO DE CUENTA
        # ----------------------------------------------

        "account_compromised": False,
        "compromised_account": "",
        "credentials_revoked": False,
        "account_blocked": False,

        # ----------------------------------------------
        # EXFILTRACIÓN
        # ----------------------------------------------

        "exfiltration_active": False,
        "exfiltration_blocked": False,
        "exfiltrated_records": 0,

        # ----------------------------------------------
        # RANSOMWARE SIMULADO
        # ----------------------------------------------

        "ransomware_active": False,
        "affected_records": 0,
        "ransom_note_created": False,

        # ----------------------------------------------
        # CONTENCIÓN
        # ----------------------------------------------

        "host_isolated": False,
        "segment_isolated": False,
        "propagation_blocked": False,

        # ----------------------------------------------
        # DISPONIBILIDAD
        # ----------------------------------------------

        "service_available": True,

        # ----------------------------------------------
        # RECUPERACIÓN
        # ----------------------------------------------

        "recovery_status": "NONE",
        "backup_restored": False,
        "service_rebuilt": False,
        "residual_risk": False,

        # ----------------------------------------------
        # AUDITORÍA DEL ESTADO
        # ----------------------------------------------

        "last_action": "RESET",
    }


def _validate_state(
    state: dict[str, Any]
) -> None:

    stage = state.get(
        "stage"
    )

    if stage not in VALID_STAGES:

        raise ValueError(
            (
                "Estado avanzado inválido: "
                f"stage={stage}"
            )
        )

    recovery_status = state.get(
        "recovery_status"
    )

    if (
        recovery_status
        not in VALID_RECOVERY_STATES
    ):

        raise ValueError(
            (
                "Estado avanzado inválido: "
                "recovery_status="
                f"{recovery_status}"
            )
        )

    for field in (
        "exfiltrated_records",
        "affected_records",
    ):

        value = state.get(
            field,
            0
        )

        if (
            not isinstance(
                value,
                int
            )
            or value < 0
        ):

            raise ValueError(
                (
                    "Estado avanzado inválido: "
                    f"{field} debe ser "
                    "un entero >= 0."
                )
            )


def write_advanced_incident_state(
    state: dict[str, Any]
) -> None:

    _validate_state(
        state
    )

    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temporary_file = (
        STATE_FILE.with_suffix(
            ".tmp"
        )
    )

    temporary_file.write_text(
        json.dumps(
            state,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )

    temporary_file.replace(
        STATE_FILE
    )


def read_advanced_incident_state(
) -> dict[str, Any]:

    if not STATE_FILE.exists():

        state = (
            default_advanced_incident_state()
        )

        write_advanced_incident_state(
            state
        )

        return state

    try:

        state = json.loads(
            STATE_FILE.read_text(
                encoding="utf-8"
            )
        )

    except (
        json.JSONDecodeError,
        OSError
    ):

        state = (
            default_advanced_incident_state()
        )

        write_advanced_incident_state(
            state
        )

        return state

    try:

        _validate_state(
            state
        )

    except ValueError:

        state = (
            default_advanced_incident_state()
        )

        write_advanced_incident_state(
            state
        )

    return state


def reset_advanced_incident_state(
    session_id: int
) -> dict[str, Any]:

    state = (
        default_advanced_incident_state(
            session_id=session_id
        )
    )

    write_advanced_incident_state(
        state
    )

    return state


def update_advanced_incident_state(
    **changes: Any
) -> dict[str, Any]:

    state = (
        read_advanced_incident_state()
    )

    unknown_fields = (
        set(changes)
        - set(state)
    )

    if unknown_fields:

        raise ValueError(
            (
                "Campos de estado "
                "no reconocidos: "
                + ", ".join(
                    sorted(
                        unknown_fields
                    )
                )
            )
        )

    state.update(
        changes
    )

    write_advanced_incident_state(
        state
    )

    return state
