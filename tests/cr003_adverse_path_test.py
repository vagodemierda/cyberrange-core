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
            "soc_name": "Adverse SOC",
            "ir_name": "Adverse IR",
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 303,
        "CR-003 adverso: sesión creada"
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
            "No fue posible obtener ID de sesión."
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
    " CYBERRANGECORE - CR-003 ADVERSE PATH TEST"
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
        prefix="cyberrange_cr003_adverse_"
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
    # 1. INICIO
    # ======================================================

    print(
        "1. COMPROMISO INICIAL"
    )
    print(
        "-" * 76
    )

    session_id = create_session(
        core_client
    )

    response = target_client.post(
        "/advanced/compromise"
    )

    check(
        response.status_code == 200,
        "Cuenta institucional comprometida"
    )

    open_session(
        core_client,
        session_id,
        "Core detecta compromiso inicial"
    )


    # ======================================================
    # 2. MALA CLASIFICACIÓN
    # ======================================================

    print()
    print(
        "2. CLASIFICACIÓN DEFICIENTE"
    )
    print(
        "-" * 76
    )

    submit_gate(
        core_client,
        session_id,
        "GATE-000",
        "DESCARTAR",
        (
            "Se interpreta la actividad como "
            "una excepción operativa."
        )
    )

    check_decision(
        session_id,
        "GATE-000",
        "DESCARTAR"
    )

    open_session(
        core_client,
        session_id,
        (
            "El escenario continúa pese "
            "a DESCARTAR"
        )
    )


    # ======================================================
    # 3. OBSERVACIÓN SIN RESPUESTA
    # ======================================================

    submit_gate(
        core_client,
        session_id,
        "GATE-001",
        "MANTENER_OBSERVACION",
        (
            "Se decide continuar observando "
            "antes de intervenir."
        )
    )

    check_decision(
        session_id,
        "GATE-001",
        "MANTENER_OBSERVACION"
    )


    # ======================================================
    # 4. EXFILTRACIÓN
    # ======================================================

    print()
    print(
        "3. ACUMULACIÓN DE EXFILTRACIÓN"
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
            and response.json()[
                "exfiltrated_records"
            ] == 120
        ),
        (
            "Daño inicial: "
            "120 registros exfiltrados"
        )
    )

    open_session(
        core_client,
        session_id,
        "Core detecta exfiltración"
    )


    submit_gate(
        core_client,
        session_id,
        "GATE-002",
        "CONTINUAR_MONITOREO",
        (
            "Se mantiene observación "
            "sin aplicar bloqueo inmediato."
        )
    )

    check_decision(
        session_id,
        "GATE-002",
        "CONTINUAR_MONITOREO"
    )

    state = (
        read_advanced_incident_state()
    )

    check(
        state["exfiltrated_records"]
        == 180,
        (
            "Decisión deficiente incrementa "
            "exfiltración de 120 a 180"
        )
    )

    check(
        state["exfiltration_active"]
        is True,
        "Exfiltración permanece activa"
    )


    # ======================================================
    # 5. RANSOMWARE
    # ======================================================

    print()
    print(
        "4. ACUMULACIÓN DE DAÑO POR RANSOMWARE"
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
            and response.json()[
                "affected_records"
            ] == 38
        ),
        (
            "Ransomware afecta inicialmente "
            "38 recursos"
        )
    )

    open_session(
        core_client,
        session_id,
        "Core detecta ransomware"
    )


    submit_gate(
        core_client,
        session_id,
        "GATE-003",
        "NO_INTERRUMPIR",
        (
            "Se prioriza continuidad "
            "operativa inmediata."
        )
    )

    check_decision(
        session_id,
        "GATE-003",
        "NO_INTERRUMPIR"
    )

    state = (
        read_advanced_incident_state()
    )

    check(
        state["affected_records"]
        == 78,
        (
            "NO_INTERRUMPIR aumenta "
            "daño de 38 a 78"
        )
    )

    check(
        state["ransomware_active"]
        is True,
        (
            "Ransomware permanece activo "
            "antes de recuperación"
        )
    )


    # ======================================================
    # 6. RECUPERACIÓN DEFENSIVA
    # ======================================================

    print()
    print(
        "5. RECUPERACIÓN CON SERVICIO AISLADO"
    )
    print(
        "-" * 76
    )

    open_session(
        core_client,
        session_id,
        "Fase de recuperación liberada"
    )

    open_session(
        core_client,
        session_id,
        "GATE-004 disponible"
    )


    submit_gate(
        core_client,
        session_id,
        "GATE-004",
        "MANTENER_AISLAMIENTO",
        (
            "Debido al daño acumulado se "
            "mantiene el entorno aislado "
            "para continuar el análisis."
        )
    )

    check_decision(
        session_id,
        "GATE-004",
        "MANTENER_AISLAMIENTO"
    )

    state = (
        read_advanced_incident_state()
    )

    check(
        state["stage"]
        == "RECOVERING",
        (
            "El entorno no alcanza "
            "estado RECOVERED"
        )
    )

    check(
        state["recovery_status"]
        == "ISOLATED",
        (
            "Recuperación permanece "
            "en aislamiento"
        )
    )

    check(
        state["service_available"]
        is False,
        (
            "Servicio permanece "
            "indisponible"
        )
    )

    check(
        state["ransomware_active"]
        is False,
        (
            "Aislamiento detiene actividad "
            "activa de ransomware"
        )
    )

    check(
        state["exfiltrated_records"]
        == 180,
        (
            "Daño de exfiltración acumulado "
            "permanece registrado"
        )
    )

    check(
        state["affected_records"]
        == 78,
        (
            "Daño por ransomware acumulado "
            "permanece registrado"
        )
    )


    # ======================================================
    # 7. FINALIZACIÓN Y REPORTE
    # ======================================================

    print()
    print(
        "6. AFTER ACTION REPORT"
    )
    print(
        "-" * 76
    )

    response = core_client.post(
        f"/session/{session_id}/finish",
        follow_redirects=False,
    )

    check(
        response.status_code == 303,
        "Sesión adversa finalizada"
    )

    response = core_client.get(
        f"/session/{session_id}/report"
    )

    check(
        response.status_code == 200,
        "After Action Report accesible"
    )

    report_text = response.text

    expected_options = [
        "DESCARTAR",
        "MANTENER_OBSERVACION",
        "CONTINUAR_MONITOREO",
        "NO_INTERRUMPIR",
        "MANTENER_AISLAMIENTO",
    ]

    for option in expected_options:

        check(
            option in report_text,
            (
                "Reporte incluye decisión "
                f"{option}"
            )
        )


    # ======================================================
    # 8. PERSISTENCIA
    # ======================================================

    db = SessionLocal()

    try:

        decisions = (
            db.query(Decision)
            .filter(
                Decision.session_id
                == session_id
            )
            .all()
        )

        session = db.get(
            SessionRun,
            session_id
        )

    finally:
        db.close()

    check(
        len(decisions) == 5,
        (
            "Ruta adversa conserva "
            "cinco decisiones"
        )
    )

    check(
        (
            session is not None
            and session.status
            == "FINISHED"
        ),
        (
            "Ruta adversa finaliza "
            "consistentemente"
        )
    )


finally:

    print()
    print(
        "7. RESTAURACIÓN DEL ENTORNO"
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
        "Entorno previo restaurado"
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
            f"CR-003 ADVERSE PATH TEST FALLÓ "
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
        "CR-003 ADVERSE PATH TEST APROBADO"
    )
)

print(
    f"Pruebas aprobadas: {passed}"
)

print(
    "=" * 76
)
