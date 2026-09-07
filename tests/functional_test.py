from pathlib import Path
import json
import sqlite3
import sys
import time


# ==========================================================
# RAÍZ DEL PROYECTO
# ==========================================================

PROJECT_ROOT = Path(
    __file__
).resolve().parent.parent

project_root_string = str(
    PROJECT_ROOT
)

if project_root_string not in sys.path:
    sys.path.insert(
        0,
        project_root_string
    )


# ==========================================================
# IMPORTS DEL PROYECTO
# ==========================================================

from fastapi.testclient import TestClient

from core.db import SessionLocal

from core.models import (
    SessionRun,
    InjectRelease,
)

from core.main import (
    apply_containment_action,
    apply_integrity_action,
)

from core.telemetry import (
    analyze_authentication,
    analyze_compromise,
    analyze_data_integrity,
)

from target_app.app import (
    app as target_application,
)

from target_app.init_db import (
    DB_FILE,
    init_database,
    reset_academic_records,
)

from range_state import (
    read_containment_state,
    reset_containment_state,
    write_containment_state,
)

from integrity_state import (
    read_integrity_state,
    reset_integrity_state,
    write_integrity_state,
)


# ==========================================================
# ARCHIVOS
# ==========================================================

LOG_FILE = (
    PROJECT_ROOT
    / "target_app"
    / "logs"
    / "events.jsonl"
)


# ==========================================================
# RESULTADOS
# ==========================================================

errors = []


def ok(message):
    print(
        f"[OK]   {message}"
    )


def fail(message):
    print(
        f"[FAIL] {message}"
    )

    errors.append(
        message
    )


def check(
    condition,
    message
):
    if condition:
        ok(message)

    else:
        fail(message)


# ==========================================================
# TELEMETRÍA
# ==========================================================

def clear_telemetry():

    LOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    LOG_FILE.write_text(
        "",
        encoding="utf-8"
    )


def read_events():

    if not LOG_FILE.exists():
        return []

    events = []

    for line in LOG_FILE.read_text(
        encoding="utf-8"
    ).splitlines():

        line = line.strip()

        if not line:
            continue

        try:
            events.append(
                json.loads(line)
            )

        except json.JSONDecodeError:
            pass

    return events


def event_exists(
    event_type
):

    return any(
        event.get(
            "event_type"
        ) == event_type
        for event in read_events()
    )


# ==========================================================
# REGISTRO ACADÉMICO
# ==========================================================

def read_academic_record():

    connection = sqlite3.connect(
        DB_FILE
    )

    try:
        return connection.execute(
            """
            SELECT
                id,
                student_code,
                course,
                grade,
                updated_by
            FROM academic_records
            WHERE id = 1
            """
        ).fetchone()

    finally:
        connection.close()


# ==========================================================
# ESTADO ORIGINAL DEL LABORATORIO
# ==========================================================

init_database()

original_containment = (
    read_containment_state()
)

original_integrity = (
    read_integrity_state()
)

original_log = ""

if LOG_FILE.exists():

    original_log = LOG_FILE.read_text(
        encoding="utf-8"
    )


original_record = (
    read_academic_record()
)


# ==========================================================
# CLIENTE DE PRUEBA
# ==========================================================

client = TestClient(
    target_application
)

db = SessionLocal()


print()
print("=" * 68)
print(" CYBERRANGECORE - FUNCTIONAL TEST")
print("=" * 68)
print()


try:

    # ======================================================
    # CR-001
    # ======================================================

    print("1. CR-001 - ACCESO NO AUTORIZADO")
    print("-" * 68)

    clear_telemetry()

    session_cr001 = SessionRun(
        scenario_id="CR-001",
        started_ts=time.time(),
        status="RUNNING",
        roles_json=json.dumps(
            {
                "SOC_ANALYST": (
                    "FUNCTIONAL_TEST"
                ),
                "IR_LEAD": (
                    "FUNCTIONAL_TEST"
                ),
            }
        ),
    )

    db.add(
        session_cr001
    )

    db.flush()


    reset_containment_state(
        session_cr001.id
    )


    # ------------------------------------------------------
    # 1.1 AUTENTICACIONES FALLIDAS
    # ------------------------------------------------------

    for number in range(3):

        response = client.post(
            "/login",
            data={
                "username": (
                    f"invalid_user_{number}"
                ),
                "password": (
                    "invalid_password"
                ),
            },
        )

        check(
            response.status_code
            == 200,
            (
                "CR-001: intento de "
                "autenticación fallido "
                f"{number + 1}"
            )
        )


    authentication = (
        analyze_authentication(
            window_minutes=5,
            failure_threshold=3
        )
    )

    check(
        authentication.get(
            "status"
        ) == "ALERT",
        (
            "CR-001: detector "
            "AUTHENTICATION = ALERT"
        )
    )

    check(
        authentication.get(
            "login_failures"
        ) >= 3,
        (
            "CR-001: detector registra "
            "al menos 3 LOGIN_FAILURE"
        )
    )


    # ------------------------------------------------------
    # 1.2 BYPASS DE AUTENTICACIÓN
    # ------------------------------------------------------

    response = client.post(
        "/login",
        data={
            "username": (
                "' OR 1=1 -- "
            ),
            "password": (
                "prueba"
            ),
        },
    )

    check(
        response.status_code
        in {
            200,
            303,
        },
        (
            "CR-001: bypass alcanza "
            "el flujo vulnerable"
        )
    )

    check(
        event_exists(
            "AUTH_BYPASS"
        ),
        (
            "CR-001: telemetría "
            "AUTH_BYPASS registrada"
        )
    )


    compromise = (
        analyze_compromise(
            window_minutes=10
        )
    )

    check(
        compromise.get(
            "status"
        ) == "COMPROMISED",
        (
            "CR-001: detector "
            "COMPROMISE = COMPROMISED"
        )
    )


    # ------------------------------------------------------
    # PERSISTIR EVIDENCIA PARA INJ-004
    # ------------------------------------------------------

    compromise_release = (
        InjectRelease(
            session_id=(
                session_cr001.id
            ),
            inject_id="INJ-004",
            released_ts=time.time(),
            telemetry_json=json.dumps(
                compromise,
                ensure_ascii=False
            ),
        )
    )

    db.add(
        compromise_release
    )

    db.flush()


    # ------------------------------------------------------
    # 1.3 CONTENCIÓN PARCIAL
    # ------------------------------------------------------

    containment_ok, _ = (
        apply_containment_action(
            db,
            session_cr001,
            "PARCIAL"
        )
    )

    check(
        containment_ok,
        (
            "CR-001: PARCIAL "
            "aceptada por el motor"
        )
    )

    containment_state = (
        read_containment_state()
    )

    check(
        containment_state.get(
            "mode"
        ) == "PARTIAL",
        (
            "CR-001: estado "
            "PARTIAL aplicado"
        )
    )

    blocked_ips = (
        containment_state.get(
            "blocked_ips"
        )
        or []
    )

    check(
        len(blocked_ips) >= 1,
        (
            "CR-001: existe IP "
            "bloqueada"
        )
    )


    response = client.post(
        "/login",
        data={
            "username": (
                "' OR 1=1 -- "
            ),
            "password": "prueba",
        },
    )

    check(
        response.status_code
        == 403,
        (
            "CR-001: PARCIAL "
            "bloquea la fuente atacante"
        )
    )

    check(
        event_exists(
            "CONTAINMENT_BLOCK"
        ),
        (
            "CR-001: evento "
            "CONTAINMENT_BLOCK registrado"
        )
    )


    # ------------------------------------------------------
    # 1.4 CONTENCIÓN TOTAL
    # ------------------------------------------------------

    containment_ok, _ = (
        apply_containment_action(
            db,
            session_cr001,
            "TOTAL"
        )
    )

    check(
        containment_ok,
        (
            "CR-001: TOTAL "
            "aceptada por el motor"
        )
    )

    containment_state = (
        read_containment_state()
    )

    check(
        containment_state.get(
            "mode"
        ) == "ISOLATED",
        (
            "CR-001: estado "
            "ISOLATED aplicado"
        )
    )


    response = client.post(
        "/login",
        data={
            "username": (
                "estudiante"
            ),
            "password": (
                "Demo-2026"
            ),
        },
    )

    check(
        response.status_code
        == 503,
        (
            "CR-001: TOTAL "
            "aísla autenticación"
        )
    )

    check(
        event_exists(
            "SERVICE_ISOLATED"
        ),
        (
            "CR-001: evento "
            "SERVICE_ISOLATED registrado"
        )
    )


    # ------------------------------------------------------
    # 1.5 NO ACTUAR
    # ------------------------------------------------------

    containment_ok, _ = (
        apply_containment_action(
            db,
            session_cr001,
            "NO_ACTUAR"
        )
    )

    check(
        containment_ok,
        (
            "CR-001: NO_ACTUAR "
            "aceptada por el motor"
        )
    )

    containment_state = (
        read_containment_state()
    )

    check(
        containment_state.get(
            "mode"
        ) == "NONE",
        (
            "CR-001: estado NONE "
            "después de NO_ACTUAR"
        )
    )


    response = client.post(
        "/login",
        data={
            "username": (
                "' OR 1=1 -- "
            ),
            "password": (
                "prueba"
            ),
        },
    )

    check(
        response.status_code
        in {
            200,
            303,
        },
        (
            "CR-001: NO_ACTUAR "
            "mantiene el flujo vulnerable"
        )
    )

    check(
        event_exists(
            "AUTH_BYPASS"
        ),
        (
            "CR-001: AUTH_BYPASS "
            "sigue siendo posible"
        )
    )


    print()
    print("2. CR-002 - INTEGRIDAD DE INFORMACIÓN")
    print("-" * 68)


    # ======================================================
    # CR-002
    # ======================================================

    clear_telemetry()

    reset_academic_records()


    session_cr002 = SessionRun(
        scenario_id="CR-002",
        started_ts=time.time(),
        status="RUNNING",
        roles_json=json.dumps(
            {
                "SOC_ANALYST": (
                    "FUNCTIONAL_TEST"
                ),
                "IR_LEAD": (
                    "FUNCTIONAL_TEST"
                ),
            }
        ),
    )

    db.add(
        session_cr002
    )

    db.flush()


    reset_integrity_state(
        session_cr002.id
    )


    # ------------------------------------------------------
    # 2.1 DATA TAMPERING
    # ------------------------------------------------------

    response = client.post(
        "/records/update",
        data={
            "record_id": 1,
            "new_grade": 1.0,
        },
    )

    check(
        response.status_code
        == 200,
        (
            "CR-002: modificación "
            "no autorizada ejecutada"
        )
    )

    check(
        event_exists(
            "DATA_TAMPERING"
        ),
        (
            "CR-002: evento "
            "DATA_TAMPERING registrado"
        )
    )


    integrity_detection = (
        analyze_data_integrity(
            window_minutes=10
        )
    )

    check(
        integrity_detection.get(
            "status"
        ) == "TAMPERED",
        (
            "CR-002: detector "
            "DATA_INTEGRITY = TAMPERED"
        )
    )


    record = (
        read_academic_record()
    )

    check(
        record is not None
        and float(record[3]) == 1.0,
        (
            "CR-002: dato alterado "
            "a 1.0"
        )
    )


    # ------------------------------------------------------
    # 2.2 RESTAURAR
    # ------------------------------------------------------

    integrity_ok, _ = (
        apply_integrity_action(
            session_cr002,
            "RESTAURAR"
        )
    )

    check(
        integrity_ok,
        (
            "CR-002: RESTAURAR "
            "aceptada por el motor"
        )
    )


    integrity_state = (
        read_integrity_state()
    )

    check(
        integrity_state.get(
            "mode"
        ) == "PROTECTED",
        (
            "CR-002: estado "
            "PROTECTED aplicado"
        )
    )


    record = (
        read_academic_record()
    )

    check(
        record is not None
        and float(record[3]) == 4.5,
        (
            "CR-002: registro "
            "restaurado a 4.5"
        )
    )


    response = client.post(
        "/records/update",
        data={
            "record_id": 1,
            "new_grade": 2.0,
        },
    )

    check(
        response.status_code
        == 403,
        (
            "CR-002: PROTECTED "
            "bloquea nueva alteración"
        )
    )

    check(
        event_exists(
            "INTEGRITY_BLOCK"
        ),
        (
            "CR-002: evento "
            "INTEGRITY_BLOCK registrado"
        )
    )


    # ------------------------------------------------------
    # 2.3 AISLAR
    # ------------------------------------------------------

    integrity_ok, _ = (
        apply_integrity_action(
            session_cr002,
            "AISLAR"
        )
    )

    check(
        integrity_ok,
        (
            "CR-002: AISLAR "
            "aceptada por el motor"
        )
    )


    integrity_state = (
        read_integrity_state()
    )

    check(
        integrity_state.get(
            "mode"
        ) == "ISOLATED",
        (
            "CR-002: estado "
            "ISOLATED aplicado"
        )
    )


    response = client.post(
        "/records/update",
        data={
            "record_id": 1,
            "new_grade": 2.0,
        },
    )

    check(
        response.status_code
        == 503,
        (
            "CR-002: AISLAR "
            "deshabilita edición"
        )
    )

    check(
        event_exists(
            "RECORDS_ISOLATED"
        ),
        (
            "CR-002: evento "
            "RECORDS_ISOLATED registrado"
        )
    )


    # ------------------------------------------------------
    # 2.4 NO ACTUAR
    # ------------------------------------------------------

    integrity_ok, _ = (
        apply_integrity_action(
            session_cr002,
            "NO_ACTUAR"
        )
    )

    check(
        integrity_ok,
        (
            "CR-002: NO_ACTUAR "
            "aceptada por el motor"
        )
    )


    integrity_state = (
        read_integrity_state()
    )

    check(
        integrity_state.get(
            "mode"
        ) == "NONE",
        (
            "CR-002: estado NONE "
            "después de NO_ACTUAR"
        )
    )


    response = client.post(
        "/records/update",
        data={
            "record_id": 1,
            "new_grade": 2.0,
        },
    )

    check(
        response.status_code
        == 200,
        (
            "CR-002: NO_ACTUAR "
            "mantiene modificación posible"
        )
    )


    record = (
        read_academic_record()
    )

    check(
        record is not None
        and float(record[3]) == 2.0,
        (
            "CR-002: registro "
            "vuelve a alterarse a 2.0"
        )
    )

    check(
        event_exists(
            "DATA_TAMPERING"
        ),
        (
            "CR-002: DATA_TAMPERING "
            "continúa siendo posible"
        )
    )


finally:

    # ======================================================
    # RESTAURACIÓN DEL LABORATORIO
    # ======================================================

    print()
    print("3. RESTAURACIÓN DEL LABORATORIO")
    print("-" * 68)

    try:

        db.rollback()

        ok(
            "Sesiones sintéticas descartadas"
        )

    except Exception as error:

        fail(
            "No fue posible descartar "
            f"sesiones sintéticas: {error}"
        )


    try:

        if original_containment:

            write_containment_state(
                session_id=(
                    original_containment.get(
                        "session_id"
                    )
                ),
                mode=(
                    original_containment.get(
                        "mode",
                        "NONE"
                    )
                ),
                blocked_ips=(
                    original_containment.get(
                        "blocked_ips",
                        []
                    )
                ),
                reason=(
                    original_containment.get(
                        "reason",
                        ""
                    )
                ),
            )

        ok(
            "Estado de contención restaurado"
        )

    except Exception as error:

        fail(
            "No fue posible restaurar "
            f"contención: {error}"
        )


    try:

        if original_integrity:

            write_integrity_state(
                session_id=(
                    original_integrity.get(
                        "session_id"
                    )
                ),
                mode=(
                    original_integrity.get(
                        "mode",
                        "NONE"
                    )
                ),
                reason=(
                    original_integrity.get(
                        "reason",
                        ""
                    )
                ),
            )

        ok(
            "Estado de integridad restaurado"
        )

    except Exception as error:

        fail(
            "No fue posible restaurar "
            f"integridad: {error}"
        )


    try:

        if original_record:

            connection = sqlite3.connect(
                DB_FILE
            )

            connection.execute(
                """
                UPDATE academic_records
                SET grade = ?,
                    updated_by = ?
                WHERE id = ?
                """,
                (
                    original_record[3],
                    original_record[4],
                    original_record[0],
                )
            )

            connection.commit()
            connection.close()

        ok(
            "Registro académico restaurado"
        )

    except Exception as error:

        fail(
            "No fue posible restaurar "
            f"registro académico: {error}"
        )


    try:

        LOG_FILE.write_text(
            original_log,
            encoding="utf-8"
        )

        ok(
            "Telemetría previa restaurada"
        )

    except Exception as error:

        fail(
            "No fue posible restaurar "
            f"telemetría: {error}"
        )


    db.close()


# ==========================================================
# RESULTADO
# ==========================================================

print()
print("=" * 68)

if errors:

    print(
        f"RESULTADO: FUNCTIONAL TEST "
        f"CON {len(errors)} ERROR(ES)"
    )

    print()

    for error in errors:
        print(
            f" - {error}"
        )

    print("=" * 68)
    print()

    sys.exit(1)


print(
    "RESULTADO: CYBERRANGECORE "
    "FUNCTIONAL TEST APROBADO"
)

print("=" * 68)
print()

sys.exit(0)
