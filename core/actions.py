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
    read_advanced_incident_state,
    update_advanced_incident_state,
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
    "ADVANCED_IDENTITY_RESPONSE",
    "ADVANCED_EXFILTRATION_RESPONSE",
    "ADVANCED_RANSOMWARE_RESPONSE",
    "ADVANCED_RECOVERY_RESPONSE",
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
# INCIDENTE AVANZADO - IDENTIDAD
# ==========================================================

def _validate_advanced_session(
    session: SessionRun
) -> tuple[bool, str]:

    state = read_advanced_incident_state()

    state_session_id = state.get(
        "session_id"
    )

    if (
        state_session_id is not None
        and state_session_id != session.id
    ):
        return (
            False,
            "El estado avanzado pertenece "
            "a otra sesión."
        )

    return (
        True,
        ""
    )


def apply_advanced_identity_action(
    session: SessionRun,
    option_key: str
) -> tuple[bool, str]:

    valid, reason = (
        _validate_advanced_session(
            session
        )
    )

    if not valid:
        return (
            False,
            reason
        )

    if option_key == "REVOCAR_CREDENCIALES":

        update_advanced_incident_state(
            credentials_revoked=True,
            last_action="CREDENTIALS_REVOKED"
        )

        return (
            True,
            "Credenciales comprometidas revocadas."
        )

    if option_key == "ESCALAR":

        update_advanced_incident_state(
            last_action="INCIDENT_ESCALATED"
        )

        return (
            True,
            "Incidente escalado al Líder IR."
        )

    if option_key == "MANTENER_OBSERVACION":

        update_advanced_incident_state(
            last_action="IDENTITY_MONITORING"
        )

        return (
            True,
            "La cuenta permanece bajo observación."
        )

    return (
        False,
        "Opción de respuesta de identidad no reconocida."
    )


# ==========================================================
# INCIDENTE AVANZADO - EXFILTRACIÓN
# ==========================================================

def apply_advanced_exfiltration_action(
    session: SessionRun,
    option_key: str
) -> tuple[bool, str]:

    valid, reason = (
        _validate_advanced_session(
            session
        )
    )

    if not valid:
        return (
            False,
            reason
        )

    state = read_advanced_incident_state()

    if option_key == "BLOQUEAR_CUENTA":

        update_advanced_incident_state(
            account_blocked=True,
            exfiltration_active=False,
            exfiltration_blocked=True,
            last_action="ACCOUNT_BLOCKED"
        )

        return (
            True,
            "Cuenta comprometida bloqueada."
        )

    if option_key == "AISLAR_SERVICIO":

        update_advanced_incident_state(
            service_available=False,
            exfiltration_active=False,
            exfiltration_blocked=True,
            last_action="SERVICE_ISOLATED"
        )

        return (
            True,
            "Servicio afectado aislado."
        )

    if option_key == "CONTINUAR_MONITOREO":

        current_records = int(
            state.get(
                "exfiltrated_records",
                0
            )
        )

        update_advanced_incident_state(
            exfiltration_active=True,
            exfiltrated_records=(
                current_records + 60
            ),
            last_action="EXFILTRATION_MONITORED"
        )

        return (
            True,
            "La exfiltración continúa bajo monitoreo."
        )

    return (
        False,
        "Opción de contención de exfiltración "
        "no reconocida."
    )


# ==========================================================
# INCIDENTE AVANZADO - RANSOMWARE
# ==========================================================

def apply_advanced_ransomware_action(
    session: SessionRun,
    option_key: str
) -> tuple[bool, str]:

    valid, reason = (
        _validate_advanced_session(
            session
        )
    )

    if not valid:
        return (
            False,
            reason
        )

    state = read_advanced_incident_state()

    if option_key == "AISLAR_HOST":

        update_advanced_incident_state(
            stage="CONTAINED",
            host_isolated=True,
            ransomware_active=False,
            propagation_blocked=True,
            last_action="HOST_ISOLATED"
        )

        return (
            True,
            "Host comprometido aislado."
        )

    if option_key == "AISLAR_SEGMENTO":

        update_advanced_incident_state(
            stage="CONTAINED",
            segment_isolated=True,
            ransomware_active=False,
            propagation_blocked=True,
            service_available=False,
            last_action="SEGMENT_ISOLATED"
        )

        return (
            True,
            "Segmento afectado aislado."
        )

    if option_key == "NO_INTERRUMPIR":

        affected_records = int(
            state.get(
                "affected_records",
                0
            )
        )

        update_advanced_incident_state(
            stage="RANSOMWARE_ACTIVE",
            ransomware_active=True,
            affected_records=(
                affected_records + 40
            ),
            last_action="RANSOMWARE_PROPAGATING"
        )

        return (
            True,
            "La actividad continúa sin aislamiento."
        )

    return (
        False,
        "Opción de respuesta a ransomware "
        "no reconocida."
    )


# ==========================================================
# INCIDENTE AVANZADO - RECUPERACIÓN
# ==========================================================

def apply_advanced_recovery_action(
    session: SessionRun,
    option_key: str
) -> tuple[bool, str]:

    valid, reason = (
        _validate_advanced_session(
            session
        )
    )

    if not valid:
        return (
            False,
            reason
        )

    if option_key == "RESTAURAR_BACKUP":

        update_advanced_incident_state(
            stage="RECOVERED",
            recovery_status="BACKUP_RESTORED",
            backup_restored=True,
            service_available=True,
            ransomware_active=False,
            residual_risk=True,
            last_action="BACKUP_RESTORED"
        )

        return (
            True,
            "Servicio restaurado desde respaldo."
        )

    if option_key == "RECONSTRUIR_SERVICIO":

        update_advanced_incident_state(
            stage="RECOVERED",
            recovery_status="SERVICE_REBUILT",
            service_rebuilt=True,
            service_available=True,
            ransomware_active=False,
            residual_risk=False,
            last_action="SERVICE_REBUILT"
        )

        return (
            True,
            "Servicio reconstruido desde una base limpia."
        )

    if option_key == "MANTENER_AISLAMIENTO":

        update_advanced_incident_state(
            stage="RECOVERING",
            recovery_status="ISOLATED",
            service_available=False,
            ransomware_active=False,
            last_action="ISOLATION_MAINTAINED"
        )

        return (
            True,
            "El aislamiento se mantiene."
        )

    return (
        False,
        "Opción de recuperación no reconocida."
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


def _execute_advanced_identity(
    db,
    session: SessionRun,
    option_key: str
) -> tuple[bool, str]:

    return apply_advanced_identity_action(
        session,
        option_key
    )


def _execute_advanced_exfiltration(
    db,
    session: SessionRun,
    option_key: str
) -> tuple[bool, str]:

    return apply_advanced_exfiltration_action(
        session,
        option_key
    )


def _execute_advanced_ransomware(
    db,
    session: SessionRun,
    option_key: str
) -> tuple[bool, str]:

    return apply_advanced_ransomware_action(
        session,
        option_key
    )


def _execute_advanced_recovery(
    db,
    session: SessionRun,
    option_key: str
) -> tuple[bool, str]:

    return apply_advanced_recovery_action(
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
    "ADVANCED_IDENTITY_RESPONSE": (
        _execute_advanced_identity
    ),
    "ADVANCED_EXFILTRATION_RESPONSE": (
        _execute_advanced_exfiltration
    ),
    "ADVANCED_RANSOMWARE_RESPONSE": (
        _execute_advanced_ransomware
    ),
    "ADVANCED_RECOVERY_RESPONSE": (
        _execute_advanced_recovery
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
