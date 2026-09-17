import json

from core.models import (
    SessionRun,
    InjectRelease,
)

from integrity_state import (
    reset_integrity_state,
    write_integrity_state,
)

from range_state import (
    reset_containment_state,
    write_containment_state,
)

from target_app.init_db import (
    reset_academic_records,
    restore_academic_record,
)

from advanced_incident_state import (
    reset_advanced_incident_state,
)


# ==========================================================
# ACCIONES SOPORTADAS POR EL MOTOR
# ==========================================================

SUPPORTED_RESET_ACTIONS = {
    "RESET_CONTAINMENT",
    "RESET_ACADEMIC_RECORDS",
    "RESET_INTEGRITY",
    "RESET_ADVANCED_INCIDENT",
}

SUPPORTED_GATE_ACTIONS = {
    "CONTAINMENT_RESPONSE",
    "INTEGRITY_RESPONSE",
}


# ==========================================================
# CR-001 - RESPUESTA DE CONTENCIÓN
# ==========================================================

def apply_containment_action(
    db,
    session: SessionRun,
    option_key: str
) -> tuple[bool, str]:

    # --------------------------------------------------
    # CONTENCIÓN PARCIAL
    # --------------------------------------------------

    if option_key == "PARCIAL":

        compromise_release = (
            db.query(InjectRelease)
            .filter(
                InjectRelease.session_id
                == session.id,
                InjectRelease.inject_id
                == "INJ-004"
            )
            .first()
        )

        if (
            not compromise_release
            or not compromise_release.telemetry_json
        ):
            return (
                False,
                "No existe evidencia técnica "
                "persistida para aplicar "
                "la contención parcial."
            )

        try:
            telemetry = json.loads(
                compromise_release.telemetry_json
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):
            return (
                False,
                "La evidencia técnica de INJ-004 "
                "no pudo ser interpretada."
            )

        latest_compromise = (
            telemetry.get(
                "latest_compromise"
            )
            or {}
        )

        source_ip = latest_compromise.get(
            "source_ip"
        )

        if not source_ip:

            compromise_events = (
                telemetry.get(
                    "compromise_events"
                )
                or []
            )

            if compromise_events:
                source_ip = (
                    compromise_events[-1]
                    .get("source_ip")
                )

        if (
            not source_ip
            or source_ip == "unknown"
        ):
            return (
                False,
                "No fue posible identificar "
                "la IP origen del compromiso."
            )

        write_containment_state(
            session_id=session.id,
            mode="PARTIAL",
            blocked_ips=[
                source_ip
            ],
            reason=(
                "Contención parcial autorizada "
                f"desde GATE-002. IP bloqueada: "
                f"{source_ip}"
            ),
        )

        return (
            True,
            (
                "Contención parcial aplicada. "
                f"IP bloqueada: {source_ip}"
            )
        )

    # --------------------------------------------------
    # CONTENCIÓN TOTAL
    # --------------------------------------------------

    if option_key == "TOTAL":

        write_containment_state(
            session_id=session.id,
            mode="ISOLATED",
            blocked_ips=[],
            reason=(
                "Contención total autorizada "
                "desde GATE-002. Servicio de "
                "autenticación aislado."
            ),
        )

        return (
            True,
            "Servicio de autenticación aislado."
        )

    # --------------------------------------------------
    # SIN CONTENCIÓN
    # --------------------------------------------------

    if option_key == "NO_ACTUAR":

        write_containment_state(
            session_id=session.id,
            mode="NONE",
            blocked_ips=[],
            reason=(
                "GATE-002 finalizado sin "
                "aplicar medidas de contención."
            ),
        )

        return (
            True,
            "No se aplicaron medidas de contención."
        )

    return (
        False,
        "Opción de contención no reconocida."
    )


# ==========================================================
# CR-002 - RESPUESTA DE INTEGRIDAD
# ==========================================================

def apply_integrity_action(
    session: SessionRun,
    option_key: str
) -> tuple[bool, str]:

    # --------------------------------------------------
    # RESTAURAR Y PROTEGER
    # --------------------------------------------------

    if option_key == "RESTAURAR":

        restore_academic_record()

        write_integrity_state(
            session_id=session.id,
            mode="PROTECTED",
            reason=(
                "Registro académico restaurado al "
                "valor legítimo y edición no autorizada "
                "bloqueada desde GATE-002."
            ),
        )

        return (
            True,
            "Registro restaurado y protegido."
        )

    # --------------------------------------------------
    # AISLAR MÓDULO
    # --------------------------------------------------

    if option_key == "AISLAR":

        write_integrity_state(
            session_id=session.id,
            mode="ISOLATED",
            reason=(
                "Módulo académico aislado "
                "desde GATE-002."
            ),
        )

        return (
            True,
            "Módulo académico aislado."
        )

    # --------------------------------------------------
    # NO ACTUAR
    # --------------------------------------------------

    if option_key == "NO_ACTUAR":

        write_integrity_state(
            session_id=session.id,
            mode="NONE",
            reason=(
                "GATE-002 finalizado sin aplicar "
                "medidas de protección de integridad."
            ),
        )

        return (
            True,
            "No se aplicaron medidas de respuesta."
        )

    return (
        False,
        "Opción de respuesta de integridad no reconocida."
    )


# ==========================================================
# RESETTERS GENÉRICOS
# ==========================================================

def _reset_containment(
    session_id: int
) -> None:

    reset_containment_state(
        session_id
    )


def _reset_academic_records(
    session_id: int
) -> None:

    reset_academic_records()


def _reset_integrity(
    session_id: int
) -> None:

    reset_integrity_state(
        session_id
    )


def _reset_advanced_incident(
    session_id: int
) -> None:

    reset_advanced_incident_state(
        session_id
    )


RESET_ACTION_HANDLERS = {
    "RESET_CONTAINMENT": (
        _reset_containment
    ),
    "RESET_ACADEMIC_RECORDS": (
        _reset_academic_records
    ),
    "RESET_INTEGRITY": (
        _reset_integrity
    ),
    "RESET_ADVANCED_INCIDENT": (
        _reset_advanced_incident
    ),
}


# ==========================================================
# ACCIONES DE GATE GENÉRICAS
# ==========================================================

def _execute_containment(
    db,
    session: SessionRun,
    option_key: str
) -> tuple[bool, str]:

    return apply_containment_action(
        db,
        session,
        option_key
    )


def _execute_integrity(
    db,
    session: SessionRun,
    option_key: str
) -> tuple[bool, str]:

    return apply_integrity_action(
        session,
        option_key
    )


GATE_ACTION_HANDLERS = {
    "CONTAINMENT_RESPONSE": (
        _execute_containment
    ),
    "INTEGRITY_RESPONSE": (
        _execute_integrity
    ),
}


# ==========================================================
# MOTOR DE REINICIO
# ==========================================================

def reset_scenario_runtime(
    scenario: dict,
    session_id: int
) -> tuple[bool, str]:

    runtime = scenario.get(
        "runtime",
        {}
    )

    reset_actions = runtime.get(
        "reset_actions",
        []
    )

    for action_name in reset_actions:

        handler = (
            RESET_ACTION_HANDLERS.get(
                action_name
            )
        )

        if not handler:
            return (
                False,
                (
                    "Acción de reinicio "
                    f"no reconocida: {action_name}"
                )
            )

        handler(
            session_id
        )

    return (
        True,
        ""
    )


# ==========================================================
# MOTOR DE CONSECUENCIAS TÉCNICAS
# ==========================================================

def execute_gate_action(
    scenario: dict,
    gate_id: str,
    db,
    session: SessionRun,
    option_key: str
) -> tuple[bool, str]:

    technical_actions = scenario.get(
        "technical_actions",
        {}
    )

    action_name = technical_actions.get(
        gate_id
    )

    # El gate no tiene consecuencia técnica configurada.
    if not action_name:
        return (
            True,
            ""
        )

    handler = (
        GATE_ACTION_HANDLERS.get(
            action_name
        )
    )

    if not handler:
        return (
            False,
            (
                "Acción técnica "
                f"no reconocida: {action_name}"
            )
        )

    return handler(
        db,
        session,
        option_key
    )
