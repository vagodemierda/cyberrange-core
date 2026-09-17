import sys
import shutil
import tempfile

from pathlib import Path
from types import SimpleNamespace


PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT)
    )


from fastapi.testclient import TestClient

from target_app.app import (
    app as target_application,
)

from core.actions import (
    execute_gate_action,
)

from core.scenario_loader import (
    load_scenario,
)

from core.telemetry import (
    run_detector,
)

from advanced_incident_state import (
    STATE_FILE,
    reset_advanced_incident_state,
    read_advanced_incident_state,
)


# ==========================================================
# PATHS
# ==========================================================

TELEMETRY_LOG = (
    PROJECT_ROOT
    / "target_app"
    / "logs"
    / "events.jsonl"
)


# ==========================================================
# TEST STATE
# ==========================================================

passed = 0
failed = 0

SESSION_ID = 99003

scenario = load_scenario(
    "CR-003"
)

session = SimpleNamespace(
    id=SESSION_ID
)


def ok(
    message: str
) -> None:

    global passed

    passed += 1

    print(
        f"[OK]   {message}"
    )


def fail(
    message: str
) -> None:

    global failed

    failed += 1

    print(
        f"[FAIL] {message}"
    )


def check(
    condition: bool,
    message: str
) -> None:

    if condition:
        ok(
            message
        )

    else:
        fail(
            message
        )


def clear_telemetry() -> None:

    TELEMETRY_LOG.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    TELEMETRY_LOG.write_text(
        "",
        encoding="utf-8"
    )


def reset_case() -> None:

    reset_advanced_incident_state(
        SESSION_ID
    )

    clear_telemetry()


def action(
    gate_id: str,
    option_key: str
) -> tuple[bool, str]:

    return execute_gate_action(
        scenario,
        gate_id,
        None,
        session,
        option_key
    )


def trigger_compromise(
    client: TestClient
):

    return client.post(
        "/advanced/compromise"
    )


def trigger_exfiltration(
    client: TestClient
):

    return client.post(
        "/advanced/exfiltrate"
    )


def trigger_ransomware(
    client: TestClient
):

    return client.post(
        "/advanced/ransomware"
    )


def prepare_exfiltration(
    client: TestClient
) -> None:

    compromise = trigger_compromise(
        client
    )

    if compromise.status_code != 200:
        raise RuntimeError(
            "No fue posible preparar compromiso."
        )

    exfiltration = trigger_exfiltration(
        client
    )

    if exfiltration.status_code != 200:
        raise RuntimeError(
            "No fue posible preparar exfiltración."
        )


def prepare_ransomware(
    client: TestClient
) -> None:

    prepare_exfiltration(
        client
    )

    ransomware = trigger_ransomware(
        client
    )

    if ransomware.status_code != 200:
        raise RuntimeError(
            "No fue posible preparar ransomware."
        )


def copy_if_exists(
    source: Path,
    destination: Path
) -> bool:

    if not source.exists():
        return False

    destination.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    shutil.copy2(
        source,
        destination
    )

    return True


def restore_file(
    backup: Path,
    destination: Path,
    existed_before: bool
) -> None:

    if existed_before:

        destination.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        shutil.copy2(
            backup,
            destination
        )

    elif destination.exists():

        destination.unlink()


print()
print(
    "=" * 72
)
print(
    " CYBERRANGECORE - CR-003 FUNCTIONAL TEST"
)
print(
    "=" * 72
)
print()


# ==========================================================
# BACKUP
# ==========================================================

backup_dir = Path(
    tempfile.mkdtemp(
        prefix="cyberrange_cr003_"
    )
)

files = {
    "telemetry": TELEMETRY_LOG,
    "advanced_state": STATE_FILE,
}

existed = {}

for key, path in files.items():

    backup = (
        backup_dir
        / key
    )

    existed[key] = copy_if_exists(
        path,
        backup
    )


client = None


try:

    client = TestClient(
        target_application
    )


    # ======================================================
    # 1. DETECTORES
    # ======================================================

    print(
        "1. TELEMETRÍA AVANZADA"
    )
    print(
        "-" * 72
    )

    reset_case()

    response = trigger_compromise(
        client
    )

    check(
        response.status_code == 200,
        "Compromiso de cuenta ejecutado"
    )

    detector = run_detector(
        "ACCOUNT_COMPROMISE",
        {
            "window_minutes": 10
        }
    )

    check(
        detector["status"]
        == "COMPROMISED",
        (
            "Detector ACCOUNT_COMPROMISE "
            "= COMPROMISED"
        )
    )


    response = trigger_exfiltration(
        client
    )

    check(
        response.status_code == 200,
        "Exfiltración simulada ejecutada"
    )

    detector = run_detector(
        "EXFILTRATION",
        {
            "window_minutes": 10
        }
    )

    check(
        detector["status"]
        == "EXFILTRATING",
        (
            "Detector EXFILTRATION "
            "= EXFILTRATING"
        )
    )


    response = trigger_ransomware(
        client
    )

    check(
        response.status_code == 200,
        "Ransomware simulado ejecutado"
    )

    detector = run_detector(
        "RANSOMWARE",
        {
            "window_minutes": 10
        }
    )

    check(
        detector["status"]
        == "RANSOMWARE_ACTIVE",
        (
            "Detector RANSOMWARE "
            "= RANSOMWARE_ACTIVE"
        )
    )


    # ======================================================
    # 2. GATE-001 - IDENTIDAD
    # ======================================================

    print()
    print(
        "2. GATE-001 - RESPUESTA DE IDENTIDAD"
    )
    print(
        "-" * 72
    )


    # ------------------------------------------------------
    # REVOCAR CREDENCIALES
    # ------------------------------------------------------

    reset_case()

    trigger_compromise(
        client
    )

    accepted, reason = action(
        "GATE-001",
        "REVOCAR_CREDENCIALES"
    )

    state = read_advanced_incident_state()

    check(
        accepted,
        "REVOCAR_CREDENCIALES aceptada"
    )

    check(
        state["credentials_revoked"]
        is True,
        "Credenciales quedan revocadas"
    )


    # ------------------------------------------------------
    # ESCALAR
    # ------------------------------------------------------

    reset_case()

    trigger_compromise(
        client
    )

    accepted, reason = action(
        "GATE-001",
        "ESCALAR"
    )

    state = read_advanced_incident_state()

    check(
        accepted,
        "ESCALAR aceptada"
    )

    check(
        state["last_action"]
        == "INCIDENT_ESCALATED",
        "Escalamiento queda registrado"
    )


    # ------------------------------------------------------
    # OBSERVACIÓN
    # ------------------------------------------------------

    reset_case()

    trigger_compromise(
        client
    )

    accepted, reason = action(
        "GATE-001",
        "MANTENER_OBSERVACION"
    )

    state = read_advanced_incident_state()

    check(
        accepted,
        "MANTENER_OBSERVACION aceptada"
    )

    check(
        state["last_action"]
        == "IDENTITY_MONITORING",
        "Observación queda registrada"
    )


    # ======================================================
    # 3. GATE-002 - EXFILTRACIÓN
    # ======================================================

    print()
    print(
        "3. GATE-002 - CONTENCIÓN DE EXFILTRACIÓN"
    )
    print(
        "-" * 72
    )


    # ------------------------------------------------------
    # BLOQUEAR CUENTA
    # ------------------------------------------------------

    reset_case()

    prepare_exfiltration(
        client
    )

    accepted, reason = action(
        "GATE-002",
        "BLOQUEAR_CUENTA"
    )

    state = read_advanced_incident_state()

    check(
        accepted,
        "BLOQUEAR_CUENTA aceptada"
    )

    check(
        (
            state["account_blocked"]
            and state["exfiltration_blocked"]
        ),
        (
            "Cuenta y exfiltración "
            "quedan bloqueadas"
        )
    )

    response = trigger_exfiltration(
        client
    )

    check(
        response.status_code == 403,
        (
            "BLOQUEAR_CUENTA impide "
            "nueva exfiltración"
        )
    )


    # ------------------------------------------------------
    # AISLAR SERVICIO
    # ------------------------------------------------------

    reset_case()

    prepare_exfiltration(
        client
    )

    accepted, reason = action(
        "GATE-002",
        "AISLAR_SERVICIO"
    )

    state = read_advanced_incident_state()

    check(
        accepted,
        "AISLAR_SERVICIO aceptada"
    )

    check(
        state["service_available"]
        is False,
        "Servicio queda no disponible"
    )

    check(
        state["exfiltration_blocked"]
        is True,
        "Exfiltración queda bloqueada"
    )

    response = trigger_exfiltration(
        client
    )

    check(
        response.status_code == 403,
        (
            "Servicio aislado impide "
            "nueva exfiltración"
        )
    )


    # ------------------------------------------------------
    # CONTINUAR MONITOREO
    # ------------------------------------------------------

    reset_case()

    prepare_exfiltration(
        client
    )

    before = (
        read_advanced_incident_state()
        ["exfiltrated_records"]
    )

    accepted, reason = action(
        "GATE-002",
        "CONTINUAR_MONITOREO"
    )

    state = read_advanced_incident_state()

    check(
        accepted,
        "CONTINUAR_MONITOREO aceptada"
    )

    check(
        (
            state["exfiltrated_records"]
            == before + 60
        ),
        (
            "Continuar monitoreo aumenta "
            "el volumen exfiltrado"
        )
    )

    check(
        state["exfiltration_active"]
        is True,
        "Exfiltración permanece activa"
    )


    # ======================================================
    # 4. GATE-003 - RANSOMWARE
    # ======================================================

    print()
    print(
        "4. GATE-003 - CONTENCIÓN DE RANSOMWARE"
    )
    print(
        "-" * 72
    )


    # ------------------------------------------------------
    # AISLAR HOST
    # ------------------------------------------------------

    reset_case()

    prepare_ransomware(
        client
    )

    accepted, reason = action(
        "GATE-003",
        "AISLAR_HOST"
    )

    state = read_advanced_incident_state()

    check(
        accepted,
        "AISLAR_HOST aceptada"
    )

    check(
        (
            state["stage"]
            == "CONTAINED"
            and state["host_isolated"]
            and state["propagation_blocked"]
        ),
        "Host queda contenido"
    )

    response = trigger_ransomware(
        client
    )

    check(
        response.status_code == 403,
        (
            "AISLAR_HOST impide nueva "
            "actividad de ransomware"
        )
    )


    # ------------------------------------------------------
    # AISLAR SEGMENTO
    # ------------------------------------------------------

    reset_case()

    prepare_ransomware(
        client
    )

    accepted, reason = action(
        "GATE-003",
        "AISLAR_SEGMENTO"
    )

    state = read_advanced_incident_state()

    check(
        accepted,
        "AISLAR_SEGMENTO aceptada"
    )

    check(
        (
            state["segment_isolated"]
            and state["propagation_blocked"]
        ),
        "Segmento queda aislado"
    )

    check(
        state["service_available"]
        is False,
        (
            "Aislamiento de segmento "
            "afecta disponibilidad"
        )
    )

    response = trigger_ransomware(
        client
    )

    check(
        response.status_code == 503,
        (
            "Segmento aislado impide "
            "nueva actividad"
        )
    )


    # ------------------------------------------------------
    # NO INTERRUMPIR
    # ------------------------------------------------------

    reset_case()

    prepare_ransomware(
        client
    )

    before = (
        read_advanced_incident_state()
        ["affected_records"]
    )

    accepted, reason = action(
        "GATE-003",
        "NO_INTERRUMPIR"
    )

    state = read_advanced_incident_state()

    check(
        accepted,
        "NO_INTERRUMPIR aceptada por el motor"
    )

    check(
        (
            state["affected_records"]
            == before + 40
        ),
        (
            "NO_INTERRUMPIR incrementa "
            "el daño simulado"
        )
    )

    check(
        state["ransomware_active"]
        is True,
        "Ransomware permanece activo"
    )


    # ======================================================
    # 5. GATE-004 - RECUPERACIÓN
    # ======================================================

    print()
    print(
        "5. GATE-004 - RECUPERACIÓN"
    )
    print(
        "-" * 72
    )


    # ------------------------------------------------------
    # RESTAURAR BACKUP
    # ------------------------------------------------------

    reset_case()

    prepare_ransomware(
        client
    )

    action(
        "GATE-003",
        "AISLAR_HOST"
    )

    accepted, reason = action(
        "GATE-004",
        "RESTAURAR_BACKUP"
    )

    state = read_advanced_incident_state()

    check(
        accepted,
        "RESTAURAR_BACKUP aceptada"
    )

    check(
        (
            state["stage"]
            == "RECOVERED"
            and state["backup_restored"]
            and state["service_available"]
        ),
        "Backup recupera el servicio"
    )

    check(
        state["residual_risk"]
        is True,
        (
            "Restauración desde backup "
            "conserva riesgo residual"
        )
    )


    # ------------------------------------------------------
    # RECONSTRUIR SERVICIO
    # ------------------------------------------------------

    reset_case()

    prepare_ransomware(
        client
    )

    action(
        "GATE-003",
        "AISLAR_HOST"
    )

    accepted, reason = action(
        "GATE-004",
        "RECONSTRUIR_SERVICIO"
    )

    state = read_advanced_incident_state()

    check(
        accepted,
        "RECONSTRUIR_SERVICIO aceptada"
    )

    check(
        (
            state["stage"]
            == "RECOVERED"
            and state["service_rebuilt"]
            and state["service_available"]
        ),
        "Reconstrucción recupera el servicio"
    )

    check(
        state["residual_risk"]
        is False,
        (
            "Reconstrucción elimina "
            "riesgo residual simulado"
        )
    )


    # ------------------------------------------------------
    # MANTENER AISLAMIENTO
    # ------------------------------------------------------

    reset_case()

    prepare_ransomware(
        client
    )

    action(
        "GATE-003",
        "AISLAR_SEGMENTO"
    )

    accepted, reason = action(
        "GATE-004",
        "MANTENER_AISLAMIENTO"
    )

    state = read_advanced_incident_state()

    check(
        accepted,
        "MANTENER_AISLAMIENTO aceptada"
    )

    check(
        (
            state["stage"]
            == "RECOVERING"
            and state["recovery_status"]
            == "ISOLATED"
        ),
        (
            "Entorno permanece en "
            "recuperación aislada"
        )
    )

    check(
        state["service_available"]
        is False,
        (
            "Mantener aislamiento conserva "
            "indisponibilidad"
        )
    )


    # ======================================================
    # 6. SESIÓN INCORRECTA
    # ======================================================

    print()
    print(
        "6. AISLAMIENTO ENTRE SESIONES"
    )
    print(
        "-" * 72
    )

    reset_case()

    wrong_session = SimpleNamespace(
        id=123456
    )

    accepted, reason = (
        execute_gate_action(
            scenario,
            "GATE-001",
            None,
            wrong_session,
            "ESCALAR"
        )
    )

    check(
        accepted is False,
        (
            "Estado avanzado rechaza "
            "otra sesión"
        )
    )

    check(
        "otra sesión" in reason,
        (
            "Rechazo identifica conflicto "
            "de sesión"
        )
    )


finally:

    print()
    print(
        "7. RESTAURACIÓN DEL ENTORNO"
    )
    print(
        "-" * 72
    )

    if client is not None:

        client.close()

    ok(
        "Cliente de prueba cerrado"
    )

    for key, destination in files.items():

        backup = (
            backup_dir
            / key
        )

        restore_file(
            backup,
            destination,
            existed[key]
        )

    ok(
        "Telemetría y estado avanzado restaurados"
    )

    shutil.rmtree(
        backup_dir,
        ignore_errors=True
    )

    ok(
        "Backup temporal eliminado"
    )


print()
print(
    "=" * 72
)

if failed:

    print(
        (
            "RESULTADO: CYBERRANGECORE "
            f"CR-003 FUNCTIONAL TEST FALLÓ "
            f"({failed} errores)"
        )
    )

    print(
        "=" * 72
    )

    sys.exit(
        1
    )


print(
    (
        "RESULTADO: CYBERRANGECORE "
        "CR-003 FUNCTIONAL TEST APROBADO"
    )
)

print(
    f"Pruebas aprobadas: {passed}"
)

print(
    "=" * 72
)
