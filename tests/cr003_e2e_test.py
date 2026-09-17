import re
import sys
import shutil
import tempfile

from pathlib import Path


PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT)
    )


from fastapi.testclient import TestClient

from core.main import (
    app as core_application,
)

from core.db import (
    SessionLocal,
    engine,
)

from core.models import (
    SessionRun,
    Decision,
)

from target_app.app import (
    app as target_application,
)

from advanced_incident_state import (
    STATE_FILE,
    read_advanced_incident_state,
)


# ==========================================================
# PATHS
# ==========================================================

CORE_DB = (
    PROJECT_ROOT
    / "data"
    / "cyberrange.db"
)

TELEMETRY_LOG = (
    PROJECT_ROOT
    / "target_app"
    / "logs"
    / "events.jsonl"
)


passed = 0
failed = 0


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


def create_session(
    client: TestClient
) -> int:

    response = client.post(
        "/session/new",
        data={
            "scenario_id": "CR-003",
            "soc_name": "CR003 SOC",
            "ir_name": "CR003 IR",
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 303,
        "CR-003: creación de sesión responde 303"
    )

    location = response.headers.get(
        "location",
        ""
    )

    match = re.search(
        r"/session/(\d+)",
        location
    )

    if not match:
        raise RuntimeError(
            "No fue posible obtener ID de CR-003."
        )

    return int(
        match.group(1)
    )


def open_session(
    client: TestClient,
    session_id: int,
    message: str
) -> None:

    response = client.get(
        f"/session/{session_id}"
    )

    check(
        response.status_code == 200,
        message
    )


def submit_gate(
    client: TestClient,
    session_id: int,
    gate_id: str,
    option_key: str,
    justification: str
) -> None:

    response = client.post(
        (
            f"/session/{session_id}"
            f"/gate/{gate_id}"
        ),
        data={
            "option_key": option_key,
            "justification": justification,
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 303,
        (
            f"{gate_id}: registra "
            f"{option_key}"
        )
    )


def check_decision(
    session_id: int,
    gate_id: str,
    option_key: str
) -> None:

    db = SessionLocal()

    try:

        decision = (
            db.query(Decision)
            .filter(
                Decision.session_id
                == session_id,
                Decision.gate_id
                == gate_id
            )
            .first()
        )

        check(
            (
                decision is not None
                and decision.option_key
                == option_key
            ),
            (
                f"{gate_id}: persistió "
                f"{option_key}"
            )
        )

    finally:
        db.close()


def check_finished(
    session_id: int
) -> None:

    db = SessionLocal()

    try:

        session = db.get(
            SessionRun,
            session_id
        )

        check(
            (
                session is not None
                and session.status
                == "FINISHED"
                and session.finished_ts
                is not None
            ),
            (
                "CR-003: estado FINISHED "
                "persistido"
            )
        )

    finally:
        db.close()


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
    "=" * 76
)
print(
    " CYBERRANGECORE - CR-003 END TO END ACCEPTANCE TEST"
)
print(
    "=" * 76
)
print()


# ==========================================================
# BACKUP
# ==========================================================

engine.dispose()

backup_dir = Path(
    tempfile.mkdtemp(
        prefix="cyberrange_cr003_e2e_"
    )
)

files = {
    "core_db": CORE_DB,
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


core_client = None
target_client = None


try:

    core_client = TestClient(
        core_application
    )

    target_client = TestClient(
        target_application
    )

    clear_telemetry()


    # ======================================================
    # 1. CREAR SESIÓN
    # ======================================================

    print(
        "1. INICIO DEL INCIDENTE AVANZADO"
    )
    print(
        "-" * 76
    )

    session_id = create_session(
        core_client
    )

    state = (
        read_advanced_incident_state()
    )

    check(
        state["session_id"]
        == session_id,
        (
            "CR-003: runtime asociado "
            "a la nueva sesión"
        )
    )

    check(
        state["stage"]
        == "INITIAL",
        "CR-003: inicia en estado INITIAL"
    )


    # ======================================================
    # 2. COMPROMISO DE CUENTA
    # ======================================================

    response = target_client.post(
        "/advanced/compromise"
    )

    check(
        (
            response.status_code == 200
            and response.json()["status"]
            == "COMPROMISED"
        ),
        (
            "CR-003: compromiso de "
            "cuenta generado"
        )
    )

    open_session(
        core_client,
        session_id,
        (
            "CR-003: consola detecta "
            "compromiso inicial"
        )
    )


    # ======================================================
    # GATE-000
    # ======================================================

    submit_gate(
        core_client,
        session_id,
        "GATE-000",
        "INVESTIGAR",
        (
            "El patrón observado justifica "
            "una investigación formal."
        )
    )

    check_decision(
        session_id,
        "GATE-000",
        "INVESTIGAR"
    )

    open_session(
        core_client,
        session_id,
        (
            "CR-003: progresión posterior "
            "a GATE-000"
        )
    )


    # ======================================================
    # GATE-001
    # ======================================================

    submit_gate(
        core_client,
        session_id,
        "GATE-001",
        "ESCALAR",
        (
            "La evidencia de compromiso "
            "requiere coordinación con IR."
        )
    )

    check_decision(
        session_id,
        "GATE-001",
        "ESCALAR"
    )


    # ======================================================
    # 3. EXFILTRACIÓN
    # ======================================================

    print()
    print(
        "2. EXFILTRACIÓN Y CONTENCIÓN"
    )
    print(
        "-" * 76
    )

    response = target_client.post(
        "/advanced/exfiltrate"
    )

    check(
        (
            response.status_code == 200
            and response.json()["status"]
            == "EXFILTRATING"
        ),
        (
            "CR-003: exfiltración "
            "confirmada"
        )
    )

    check(
        response.json()[
            "exfiltrated_records"
        ] == 120,
        (
            "CR-003: 120 registros "
            "exfiltrados inicialmente"
        )
    )

    open_session(
        core_client,
        session_id,
        (
            "CR-003: consola detecta "
            "exfiltración"
        )
    )


    # ======================================================
    # GATE-002
    # ======================================================

    submit_gate(
        core_client,
        session_id,
        "GATE-002",
        "BLOQUEAR_CUENTA",
        (
            "Se bloquea la identidad "
            "comprometida para detener "
            "la transferencia."
        )
    )

    check_decision(
        session_id,
        "GATE-002",
        "BLOQUEAR_CUENTA"
    )

    state = (
        read_advanced_incident_state()
    )

    check(
        (
            state["account_blocked"]
            and state["exfiltration_blocked"]
        ),
        (
            "CR-003: GATE-002 produce "
            "contención técnica"
        )
    )

    response = target_client.post(
        "/advanced/exfiltrate"
    )

    check(
        response.status_code == 403,
        (
            "CR-003: nueva exfiltración "
            "queda bloqueada"
        )
    )


    # ======================================================
    # 4. RANSOMWARE
    # ======================================================

    print()
    print(
        "3. RANSOMWARE Y AISLAMIENTO"
    )
    print(
        "-" * 76
    )

    response = target_client.post(
        "/advanced/ransomware"
    )

    check(
        (
            response.status_code == 200
            and response.json()["status"]
            == "RANSOMWARE_ACTIVE"
        ),
        (
            "CR-003: actividad de "
            "ransomware generada"
        )
    )

    check(
        response.json()[
            "affected_records"
        ] == 38,
        (
            "CR-003: daño inicial "
            "cuantificado en 38 recursos"
        )
    )

    open_session(
        core_client,
        session_id,
        (
            "CR-003: consola detecta "
            "ransomware"
        )
    )


    # ======================================================
    # GATE-003
    # ======================================================

    submit_gate(
        core_client,
        session_id,
        "GATE-003",
        "AISLAR_HOST",
        (
            "Se aísla el host comprometido "
            "para detener la propagación "
            "preservando otros servicios."
        )
    )

    check_decision(
        session_id,
        "GATE-003",
        "AISLAR_HOST"
    )

    state = (
        read_advanced_incident_state()
    )

    check(
        (
            state["stage"]
            == "CONTAINED"
            and state["host_isolated"]
            and state["propagation_blocked"]
        ),
        (
            "CR-003: ransomware queda "
            "contenido técnicamente"
        )
    )

    response = target_client.post(
        "/advanced/ransomware"
    )

    check(
        response.status_code == 403,
        (
            "CR-003: nueva actividad "
            "de ransomware es bloqueada"
        )
    )


    # ======================================================
    # 5. RECUPERACIÓN
    # ======================================================

    print()
    print(
        "4. RECUPERACIÓN"
    )
    print(
        "-" * 76
    )

    # La consola libera consecuencia,
    # INJ-008 y posteriormente GATE-004.

    open_session(
        core_client,
        session_id,
        (
            "CR-003: fase de recuperación "
            "es liberada"
        )
    )

    open_session(
        core_client,
        session_id,
        (
            "CR-003: GATE-004 disponible"
        )
    )


    submit_gate(
        core_client,
        session_id,
        "GATE-004",
        "RECONSTRUIR_SERVICIO",
        (
            "Se prioriza una reconstrucción "
            "controlada desde una base limpia "
            "para reducir riesgo residual."
        )
    )

    check_decision(
        session_id,
        "GATE-004",
        "RECONSTRUIR_SERVICIO"
    )

    state = (
        read_advanced_incident_state()
    )

    check(
        (
            state["stage"]
            == "RECOVERED"
            and state["service_rebuilt"]
            and state["service_available"]
            and not state["residual_risk"]
        ),
        (
            "CR-003: servicio queda "
            "RECOVERED sin riesgo residual"
        )
    )


    # ======================================================
    # 6. FINALIZAR
    # ======================================================

    print()
    print(
        "5. FINALIZACIÓN Y AFTER ACTION REPORT"
    )
    print(
        "-" * 76
    )

    response = core_client.post(
        (
            f"/session/{session_id}"
            "/finish"
        ),
        follow_redirects=False,
    )

    check(
        response.status_code == 303,
        (
            "CR-003: finalización "
            "responde 303"
        )
    )

    check_finished(
        session_id
    )


    # ======================================================
    # REPORTE
    # ======================================================

    response = core_client.get(
        (
            f"/session/{session_id}"
            "/report"
        )
    )

    check(
        response.status_code == 200,
        (
            "CR-003: reporte final "
            "accesible"
        )
    )

    report_text = response.text

    check(
        "Resultados del entrenamiento"
        in report_text,
        (
            "CR-003: reporte contiene "
            "debrief final"
        )
    )

    expected_decisions = {
        "GATE-000": "INVESTIGAR",
        "GATE-001": "ESCALAR",
        "GATE-002": "BLOQUEAR_CUENTA",
        "GATE-003": "AISLAR_HOST",
        "GATE-004": "RECONSTRUIR_SERVICIO",
    }

    for (
        gate_id,
        option_key
    ) in expected_decisions.items():

        check(
            gate_id in report_text,
            (
                f"CR-003: reporte incluye "
                f"{gate_id}"
            )
        )

        check(
            option_key in report_text,
            (
                f"CR-003: reporte incluye "
                f"{option_key}"
            )
        )


    # ======================================================
    # CONSISTENCIA
    # ======================================================

    db = SessionLocal()

    try:

        decision_count = (
            db.query(Decision)
            .filter(
                Decision.session_id
                == session_id
            )
            .count()
        )

    finally:
        db.close()

    check(
        decision_count == 5,
        (
            "CR-003: existen exactamente "
            "cinco decisiones persistidas"
        )
    )


finally:

    print()
    print(
        "6. RESTAURACIÓN DEL ENTORNO"
    )
    print(
        "-" * 76
    )

    if core_client is not None:
        core_client.close()

    if target_client is not None:
        target_client.close()

    ok(
        "Clientes de prueba cerrados"
    )

    engine.dispose()

    ok(
        "Conexiones SQLite liberadas"
    )

    for key, destination in (
        files.items()
    ):

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
        "Base Core restaurada"
    )

    ok(
        "Telemetría previa restaurada"
    )

    ok(
        "Estado avanzado restaurado"
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
    "=" * 76
)

if failed:

    print(
        (
            "RESULTADO: CYBERRANGECORE "
            f"CR-003 E2E TEST FALLÓ "
            f"({failed} errores)"
        )
    )

    print(
        "=" * 76
    )

    sys.exit(
        1
    )


print(
    (
        "RESULTADO: CYBERRANGECORE "
        "CR-003 E2E ACCEPTANCE TEST APROBADO"
    )
)

print(
    f"Pruebas aprobadas: {passed}"
)

print(
    "=" * 76
)
