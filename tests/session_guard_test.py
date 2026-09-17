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

from core.main import app as core_application

from core.db import (
    SessionLocal,
    engine,
)

from core.models import (
    SessionRun,
    Decision,
    InjectRelease,
)

from target_app.app import (
    app as target_application,
)

from target_app.init_db import (
    init_database,
)


# ==========================================================
# PATHS
# ==========================================================

CORE_DB = (
    PROJECT_ROOT
    / "data"
    / "cyberrange.db"
)

TARGET_DB = (
    PROJECT_ROOT
    / "target_app"
    / "data"
    / "portal.db"
)

TELEMETRY_LOG = (
    PROJECT_ROOT
    / "target_app"
    / "logs"
    / "events.jsonl"
)

CONTAINMENT_STATE = (
    PROJECT_ROOT
    / "data"
    / "containment_state.json"
)

INTEGRITY_STATE = (
    PROJECT_ROOT
    / "data"
    / "integrity_state.json"
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
            "scenario_id": "CR-001",
            "soc_name": "Guard SOC",
            "ir_name": "Guard IR",
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 303,
        "Creación de sesión responde 303"
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
            "No fue posible obtener el ID de sesión."
        )

    return int(
        match.group(1)
    )


def decision_count(
    session_id: int,
    gate_id: str | None = None
) -> int:

    db = SessionLocal()

    try:

        query = (
            db.query(Decision)
            .filter(
                Decision.session_id
                == session_id
            )
        )

        if gate_id:

            query = query.filter(
                Decision.gate_id
                == gate_id
            )

        return query.count()

    finally:
        db.close()


def release_exists(
    session_id: int,
    inject_id: str
) -> bool:

    db = SessionLocal()

    try:

        release = (
            db.query(InjectRelease)
            .filter(
                InjectRelease.session_id
                == session_id,
                InjectRelease.inject_id
                == inject_id
            )
            .first()
        )

        return release is not None

    finally:
        db.close()


def session_status(
    session_id: int
) -> str | None:

    db = SessionLocal()

    try:

        session = db.get(
            SessionRun,
            session_id
        )

        if not session:
            return None

        return session.status

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
    "=" * 72
)
print(
    " CYBERRANGECORE - SESSION GUARD TEST"
)
print(
    "=" * 72
)
print()


# ==========================================================
# BACKUP
# ==========================================================

engine.dispose()

backup_dir = Path(
    tempfile.mkdtemp(
        prefix="cyberrange_guard_"
    )
)

files = {
    "core_db": CORE_DB,
    "target_db": TARGET_DB,
    "telemetry": TELEMETRY_LOG,
    "containment": CONTAINMENT_STATE,
    "integrity": INTEGRITY_STATE,
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

    init_database()

    core_client = TestClient(
        core_application
    )

    target_client = TestClient(
        target_application
    )

    clear_telemetry()


    # ======================================================
    # 1. SESIÓN INEXISTENTE
    # ======================================================

    print(
        "1. SESIÓN Y GATE INEXISTENTES"
    )
    print(
        "-" * 72
    )

    response = core_client.post(
        "/session/999999999/gate/GATE-000",
        data={
            "option_key": "CONFIRMAR",
            "justification": "Prueba de guard."
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 404,
        "Sesión inexistente es rechazada"
    )

    response = core_client.post(
        "/session/999999999/finish",
        follow_redirects=False,
    )

    check(
        response.status_code == 404,
        "Finalización de sesión inexistente es rechazada"
    )


    # ======================================================
    # 2. CREAR SESIÓN CONTROLADA
    # ======================================================

    print()
    print(
        "2. CONTROL DE DISPONIBILIDAD"
    )
    print(
        "-" * 72
    )

    session_id = create_session(
        core_client
    )

    response = core_client.post(
        (
            f"/session/{session_id}"
            "/gate/GATE-999"
        ),
        data={
            "option_key": "INVALID",
            "justification": "Gate inexistente."
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 404,
        "Gate inexistente es rechazado"
    )

    response = core_client.post(
        (
            f"/session/{session_id}"
            "/gate/GATE-001"
        ),
        data={
            "option_key": "ESCALAR",
            "justification": (
                "Intento anticipado."
            ),
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 403,
        "Gate anticipado es rechazado"
    )

    check(
        decision_count(
            session_id,
            "GATE-001"
        ) == 0,
        (
            "Gate anticipado no genera "
            "decisión fantasma"
        )
    )


    # ======================================================
    # 3. LIBERAR GATE-000
    # ======================================================

    print()
    print(
        "3. VALIDACIÓN DE ENTRADAS"
    )
    print(
        "-" * 72
    )

    clear_telemetry()

    for index in range(
        1,
        4
    ):

        response = target_client.post(
            "/login",
            data={
                "username": (
                    f"guard_invalid_{index}"
                ),
                "password": "incorrecta",
            },
            follow_redirects=False,
        )

        check(
            response.status_code == 200,
            (
                "LOGIN_FAILURE "
                f"{index} generado"
            )
        )

    response = core_client.get(
        f"/session/{session_id}"
    )

    check(
        response.status_code == 200,
        "Consola de sesión accesible"
    )

    check(
        release_exists(
            session_id,
            "GATE-000"
        ),
        "GATE-000 fue liberado"
    )


    # ------------------------------------------------------
    # OPCIÓN INVÁLIDA
    # ------------------------------------------------------

    response = core_client.post(
        (
            f"/session/{session_id}"
            "/gate/GATE-000"
        ),
        data={
            "option_key": "INVALID_OPTION",
            "justification": (
                "Prueba de opción inválida."
            ),
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 400,
        "Opción inválida es rechazada"
    )

    check(
        decision_count(
            session_id,
            "GATE-000"
        ) == 0,
        (
            "Opción inválida no genera "
            "decisión fantasma"
        )
    )


    # ------------------------------------------------------
    # JUSTIFICACIÓN VACÍA
    # ------------------------------------------------------

    response = core_client.post(
        (
            f"/session/{session_id}"
            "/gate/GATE-000"
        ),
        data={
            "option_key": "CONFIRMAR",
            "justification": "   ",
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 400,
        "Justificación vacía es rechazada"
    )

    check(
        decision_count(
            session_id,
            "GATE-000"
        ) == 0,
        (
            "Justificación vacía no genera "
            "decisión fantasma"
        )
    )


    # ======================================================
    # 4. DECISIÓN VÁLIDA Y DUPLICADO
    # ======================================================

    print()
    print(
        "4. DUPLICADOS Y RAMIFICACIÓN"
    )
    print(
        "-" * 72
    )

    response = core_client.post(
        (
            f"/session/{session_id}"
            "/gate/GATE-000"
        ),
        data={
            "option_key": "CONFIRMAR",
            "justification": (
                "La evidencia requiere "
                "continuar el análisis."
            ),
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 303,
        "Decisión válida GATE-000 registrada"
    )

    response = core_client.post(
        (
            f"/session/{session_id}"
            "/gate/GATE-000"
        ),
        data={
            "option_key": "CONFIRMAR",
            "justification": (
                "Segundo intento."
            ),
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 409,
        "Decisión duplicada es rechazada"
    )

    check(
        decision_count(
            session_id,
            "GATE-000"
        ) == 1,
        (
            "Duplicado no altera "
            "persistencia"
        )
    )


    # ======================================================
    # 5. RAMA MONITOREAR
    # ======================================================

    response = core_client.get(
        f"/session/{session_id}"
    )

    check(
        response.status_code == 200,
        (
            "Consola actualiza progresión "
            "del escenario"
        )
    )

    response = core_client.post(
        (
            f"/session/{session_id}"
            "/gate/GATE-001"
        ),
        data={
            "option_key": "MONITOREAR",
            "justification": (
                "Se mantiene observación "
                "antes de escalar."
            ),
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 303,
        "Rama MONITOREAR registrada"
    )

    response = core_client.post(
        (
            f"/session/{session_id}"
            "/gate/GATE-002"
        ),
        data={
            "option_key": "PARCIAL",
            "justification": (
                "Intento de acceder a "
                "otra rama."
            ),
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 403,
        "Gate de rama incorrecta es rechazado"
    )

    check(
        decision_count(
            session_id,
            "GATE-002"
        ) == 0,
        (
            "Rama incorrecta no genera "
            "decisión fantasma"
        )
    )


    # ======================================================
    # 6. FINALIZACIÓN
    # ======================================================

    print()
    print(
        "5. ESTADO FINALIZADO"
    )
    print(
        "-" * 72
    )

    response = core_client.post(
        f"/session/{session_id}/finish",
        follow_redirects=False,
    )

    check(
        response.status_code == 303,
        "Primera finalización aceptada"
    )

    check(
        session_status(
            session_id
        ) == "FINISHED",
        "Estado FINISHED persistido"
    )


    # ------------------------------------------------------
    # DECISIÓN DESPUÉS DE FINALIZAR
    # ------------------------------------------------------

    response = core_client.post(
        (
            f"/session/{session_id}"
            "/gate/GATE-001"
        ),
        data={
            "option_key": "MONITOREAR",
            "justification": (
                "Intento posterior "
                "al cierre."
            ),
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 403,
        (
            "Decisión posterior al cierre "
            "es rechazada"
        )
    )

    check(
        decision_count(
            session_id,
            "GATE-001"
        ) == 1,
        (
            "Intento posterior al cierre "
            "no altera persistencia"
        )
    )


    # ------------------------------------------------------
    # SEGUNDA FINALIZACIÓN
    # ------------------------------------------------------

    response = core_client.post(
        f"/session/{session_id}/finish",
        follow_redirects=False,
    )

    check(
        response.status_code == 409,
        "Segunda finalización es rechazada"
    )


    # ======================================================
    # 7. CONSISTENCIA FINAL
    # ======================================================

    print()
    print(
        "6. CONSISTENCIA DE PERSISTENCIA"
    )
    print(
        "-" * 72
    )

    check(
        decision_count(
            session_id
        ) == 2,
        (
            "La sesión conserva exactamente "
            "dos decisiones válidas"
        )
    )

    check(
        decision_count(
            session_id,
            "GATE-000"
        ) == 1,
        "GATE-000 tiene una sola decisión"
    )

    check(
        decision_count(
            session_id,
            "GATE-001"
        ) == 1,
        "GATE-001 tiene una sola decisión"
    )

    check(
        decision_count(
            session_id,
            "GATE-002"
        ) == 0,
        "GATE-002 no contiene decisión inválida"
    )


finally:

    print()
    print(
        "7. RESTAURACIÓN DEL ENTORNO"
    )
    print(
        "-" * 72
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
        "Estado previo del laboratorio restaurado"
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
            f"SESSION GUARD TEST FALLÓ "
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
        "SESSION GUARD TEST APROBADO"
    )
)

print(
    f"Pruebas aprobadas: {passed}"
)

print(
    "=" * 72
)
