from pathlib import Path
import json
import shutil
import sys
import tempfile


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
# IMPORTS
# ==========================================================

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
    InjectRelease,
)

from target_app.app import (
    app as target_application,
)

from target_app.init_db import (
    DB_FILE as TARGET_DB_FILE,
    init_database,
)


# ==========================================================
# ARCHIVOS DEL LABORATORIO
# ==========================================================

CORE_DB_FILE = (
    PROJECT_ROOT
    / "data"
    / "cyberrange.db"
)

LOG_FILE = (
    PROJECT_ROOT
    / "target_app"
    / "logs"
    / "events.jsonl"
)

CONTAINMENT_FILE = (
    PROJECT_ROOT
    / "data"
    / "containment_state.json"
)

INTEGRITY_FILE = (
    PROJECT_ROOT
    / "data"
    / "integrity_state.json"
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
# UTILIDADES
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


def create_session(
    client,
    scenario_id
):

    response = client.post(
        "/session/new",
        data={
            "scenario_id": scenario_id,
            "soc_name": "E2E_SOC",
            "ir_name": "E2E_IR",
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 303,
        (
            f"{scenario_id}: creación "
            "de sesión responde 303"
        )
    )

    location = response.headers.get(
        "location",
        ""
    )

    check(
        location.startswith(
            "/session/"
        ),
        (
            f"{scenario_id}: redirect "
            "hacia sesión"
        )
    )

    try:
        session_id = int(
            location.rstrip(
                "/"
            ).split("/")[-1]
        )

    except (
        ValueError,
        IndexError
    ):
        raise RuntimeError(
            (
                f"No fue posible obtener "
                f"session_id desde {location}"
            )
        )

    return session_id


def open_session(
    client,
    session_id
):

    response = client.get(
        f"/session/{session_id}"
    )

    check(
        response.status_code == 200,
        (
            f"Sesión #{session_id}: "
            "consola accesible"
        )
    )

    return response


def submit_gate(
    client,
    session_id,
    gate_id,
    option_key,
    justification
):

    response = client.post(
        (
            f"/session/{session_id}"
            f"/gate/{gate_id}"
        ),
        data={
            "option_key": option_key,
            "justification": (
                justification
            ),
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 303,
        (
            f"Sesión #{session_id}: "
            f"{gate_id} registra "
            f"{option_key}"
        )
    )

    return response


def finish_session(
    client,
    session_id
):

    response = client.post(
        f"/session/{session_id}/finish",
        follow_redirects=False,
    )

    check(
        response.status_code == 303,
        (
            f"Sesión #{session_id}: "
            "finalización responde 303"
        )
    )


def check_decision(
    session_id,
    gate_id,
    expected_option
):

    db = SessionLocal()

    try:

        decision = (
            db.query(Decision)
            .filter(
                Decision.session_id
                == session_id,
                Decision.gate_id
                == gate_id,
            )
            .first()
        )

        check(
            (
                decision is not None
                and decision.option_key
                == expected_option
            ),
            (
                f"Sesión #{session_id}: "
                f"{gate_id} persistió "
                f"{expected_option}"
            )
        )

    finally:
        db.close()


def check_finished(
    session_id
):

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
                f"Sesión #{session_id}: "
                "estado FINISHED persistido"
            )
        )

    finally:
        db.close()


# ==========================================================
# PREPARACIÓN DEL ENTORNO
# ==========================================================

init_database()

temporary_directory = (
    tempfile.mkdtemp(
        prefix="cyberrange_e2e_"
    )
)

temporary_path = Path(
    temporary_directory
)


def backup_file(
    source,
    name
):

    destination = (
        temporary_path
        / name
    )

    if source.exists():

        shutil.copy2(
            source,
            destination
        )

        return True

    return False


core_db_existed = backup_file(
    CORE_DB_FILE,
    "cyberrange.db"
)

target_db_existed = backup_file(
    TARGET_DB_FILE,
    "portal.db"
)

log_existed = backup_file(
    LOG_FILE,
    "events.jsonl"
)

containment_existed = backup_file(
    CONTAINMENT_FILE,
    "containment_state.json"
)

integrity_existed = backup_file(
    INTEGRITY_FILE,
    "integrity_state.json"
)


core_client = TestClient(
    core_application
)

target_client = TestClient(
    target_application
)


print()
print("=" * 72)
print(" CYBERRANGECORE - END TO END ACCEPTANCE TEST")
print("=" * 72)
print()


try:

    # ======================================================
    # CR-001
    # ======================================================

    print(
        "1. CR-001 - FLUJO COMPLETO "
        "DE RESPUESTA A INCIDENTE"
    )

    print("-" * 72)

    clear_telemetry()

    session_cr001 = create_session(
        core_client,
        "CR-001"
    )


    # ------------------------------------------------------
    # GENERAR ALERTA
    # ------------------------------------------------------

    for number in range(3):

        response = target_client.post(
            "/login",
            data={
                "username": (
                    f"e2e_invalid_{number}"
                ),
                "password": (
                    "invalid"
                ),
            },
        )

        check(
            response.status_code == 200,
            (
                "CR-001: LOGIN_FAILURE "
                f"{number + 1} generado"
            )
        )


    # La consola procesa la telemetría
    # y libera los primeros injects/gates.

    open_session(
        core_client,
        session_cr001
    )


    # ------------------------------------------------------
    # GATE-000
    # ------------------------------------------------------

    submit_gate(
        core_client,
        session_cr001,
        "GATE-000",
        "CONFIRMAR",
        (
            "La telemetría muestra múltiples "
            "fallos de autenticación dentro de "
            "la ventana analizada."
        ),
    )

    check_decision(
        session_cr001,
        "GATE-000",
        "CONFIRMAR"
    )


    # Refrescar para permitir progresión.

    open_session(
        core_client,
        session_cr001
    )


    # ------------------------------------------------------
    # GATE-001
    # ------------------------------------------------------

    submit_gate(
        core_client,
        session_cr001,
        "GATE-001",
        "ESCALAR",
        (
            "El incidente confirmado requiere "
            "coordinación formal con IR Lead."
        ),
    )

    check_decision(
        session_cr001,
        "GATE-001",
        "ESCALAR"
    )


    # ------------------------------------------------------
    # COMPROMISO REAL
    # ------------------------------------------------------

    response = target_client.post(
        "/login",
        data={
            "username": (
                "' OR 1=1 -- "
            ),
            "password": "prueba",
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 303,
        (
            "CR-001: bypass de "
            "autenticación ejecutado"
        )
    )


    # Primer refresh:
    # libera/persiste evidencia de compromiso.

    open_session(
        core_client,
        session_cr001
    )

    # Segundo refresh:
    # garantiza resolución de dependencias
    # release_after dentro del timeline.

    open_session(
        core_client,
        session_cr001
    )


    # ------------------------------------------------------
    # GATE-002
    # ------------------------------------------------------

    submit_gate(
        core_client,
        session_cr001,
        "GATE-002",
        "PARCIAL",
        (
            "Se bloquea la fuente del compromiso "
            "manteniendo disponible el servicio "
            "para fuentes legítimas."
        ),
    )

    check_decision(
        session_cr001,
        "GATE-002",
        "PARCIAL"
    )


    # ------------------------------------------------------
    # CONSECUENCIA TÉCNICA
    # ------------------------------------------------------

    response = target_client.post(
        "/login",
        data={
            "username": (
                "' OR 1=1 -- "
            ),
            "password": "prueba",
        },
        follow_redirects=False,
    )

    check(
        response.status_code == 403,
        (
            "CR-001: consecuencia "
            "PARCIAL bloquea atacante"
        )
    )


    # ------------------------------------------------------
    # FINALIZAR
    # ------------------------------------------------------

    finish_session(
        core_client,
        session_cr001
    )

    check_finished(
        session_cr001
    )


    # ------------------------------------------------------
    # REPORTE
    # ------------------------------------------------------

    report = core_client.get(
        f"/session/{session_cr001}/report"
    )

    check(
        report.status_code == 200,
        (
            "CR-001: reporte final "
            "accesible"
        )
    )

    report_text = report.text

    check(
        (
            "Resultados del entrenamiento"
            in report_text
        ),
        (
            "CR-001: reporte contiene "
            "debrief final"
        )
    )

    check(
        "CONFIRMAR" in report_text,
        (
            "CR-001: reporte incluye "
            "GATE-000"
        )
    )

    check(
        "ESCALAR" in report_text,
        (
            "CR-001: reporte incluye "
            "GATE-001"
        )
    )

    check(
        "PARCIAL" in report_text,
        (
            "CR-001: reporte incluye "
            "GATE-002"
        )
    )


    # ======================================================
    # CR-002
    # ======================================================

    print()
    print(
        "2. CR-002 - FLUJO COMPLETO "
        "DE INTEGRIDAD DE INFORMACIÓN"
    )

    print("-" * 72)

    clear_telemetry()

    session_cr002 = create_session(
        core_client,
        "CR-002"
    )


    # ------------------------------------------------------
    # ALTERACIÓN
    # ------------------------------------------------------

    response = target_client.post(
        "/records/update",
        data={
            "record_id": 1,
            "new_grade": 1.0,
        },
    )

    check(
        response.status_code == 200,
        (
            "CR-002: alteración "
            "de registro ejecutada"
        )
    )


    open_session(
        core_client,
        session_cr002
    )


    # ------------------------------------------------------
    # GATE-000
    # ------------------------------------------------------

    submit_gate(
        core_client,
        session_cr002,
        "GATE-000",
        "CONFIRMAR",
        (
            "La evidencia confirma una "
            "modificación no autorizada "
            "del registro académico."
        ),
    )

    check_decision(
        session_cr002,
        "GATE-000",
        "CONFIRMAR"
    )


    open_session(
        core_client,
        session_cr002
    )


    # ------------------------------------------------------
    # GATE-001
    # ------------------------------------------------------

    submit_gate(
        core_client,
        session_cr002,
        "GATE-001",
        "ESCALAR",
        (
            "La afectación de integridad "
            "requiere coordinación con "
            "el Líder IR."
        ),
    )

    check_decision(
        session_cr002,
        "GATE-001",
        "ESCALAR"
    )


    # Refrescos necesarios para liberar
    # INJ-004 y posteriormente GATE-002.

    open_session(
        core_client,
        session_cr002
    )

    open_session(
        core_client,
        session_cr002
    )


    # ------------------------------------------------------
    # GATE-002
    # ------------------------------------------------------

    submit_gate(
        core_client,
        session_cr002,
        "GATE-002",
        "RESTAURAR",
        (
            "Se restaura el valor legítimo "
            "y se protege el registro frente "
            "a nuevas modificaciones."
        ),
    )

    check_decision(
        session_cr002,
        "GATE-002",
        "RESTAURAR"
    )


    # ------------------------------------------------------
    # CONSECUENCIA TÉCNICA
    # ------------------------------------------------------

    response = target_client.post(
        "/records/update",
        data={
            "record_id": 1,
            "new_grade": 2.0,
        },
    )

    check(
        response.status_code == 403,
        (
            "CR-002: RESTAURAR protege "
            "el registro"
        )
    )


    # ------------------------------------------------------
    # FINALIZAR
    # ------------------------------------------------------

    finish_session(
        core_client,
        session_cr002
    )

    check_finished(
        session_cr002
    )


    # ------------------------------------------------------
    # REPORTE
    # ------------------------------------------------------

    report = core_client.get(
        f"/session/{session_cr002}/report"
    )

    check(
        report.status_code == 200,
        (
            "CR-002: reporte final "
            "accesible"
        )
    )

    report_text = report.text

    check(
        (
            "Resultados del entrenamiento"
            in report_text
        ),
        (
            "CR-002: reporte contiene "
            "debrief final"
        )
    )

    check(
        "CONFIRMAR" in report_text,
        (
            "CR-002: reporte incluye "
            "GATE-000"
        )
    )

    check(
        "ESCALAR" in report_text,
        (
            "CR-002: reporte incluye "
            "GATE-001"
        )
    )

    check(
        "RESTAURAR" in report_text,
        (
            "CR-002: reporte incluye "
            "GATE-002"
        )
    )


finally:

    # ======================================================
    # RESTAURACIÓN EXACTA DEL LABORATORIO
    # ======================================================

    print()
    print(
        "3. RESTAURACIÓN DEL ENTORNO"
    )

    print("-" * 72)


    # Cerrar clientes.

    try:

        core_client.close()
        target_client.close()

        ok(
            "Clientes de prueba cerrados"
        )

    except Exception as error:

        fail(
            (
                "No fue posible cerrar "
                f"clientes: {error}"
            )
        )


    # Liberar conexiones SQLite del Core.

    try:

        engine.dispose()

        ok(
            "Conexiones SQLite liberadas"
        )

    except Exception as error:

        fail(
            (
                "No fue posible liberar "
                f"SQLite: {error}"
            )
        )


    # Restaurar base del Core.

    try:

        backup = (
            temporary_path
            / "cyberrange.db"
        )

        if core_db_existed:

            shutil.copy2(
                backup,
                CORE_DB_FILE
            )

        elif CORE_DB_FILE.exists():

            CORE_DB_FILE.unlink()

        ok(
            "Base CyberRangeCore restaurada"
        )

    except Exception as error:

        fail(
            (
                "No fue posible restaurar "
                f"base Core: {error}"
            )
        )


    # Restaurar base Target.

    try:

        backup = (
            temporary_path
            / "portal.db"
        )

        if target_db_existed:

            shutil.copy2(
                backup,
                TARGET_DB_FILE
            )

        elif TARGET_DB_FILE.exists():

            TARGET_DB_FILE.unlink()

        ok(
            "Base Target restaurada"
        )

    except Exception as error:

        fail(
            (
                "No fue posible restaurar "
                f"base Target: {error}"
            )
        )


    # Restaurar telemetría.

    try:

        backup = (
            temporary_path
            / "events.jsonl"
        )

        if log_existed:

            shutil.copy2(
                backup,
                LOG_FILE
            )

        elif LOG_FILE.exists():

            LOG_FILE.unlink()

        ok(
            "Telemetría previa restaurada"
        )

    except Exception as error:

        fail(
            (
                "No fue posible restaurar "
                f"telemetría: {error}"
            )
        )


    # Restaurar estado de contención.

    try:

        backup = (
            temporary_path
            / "containment_state.json"
        )

        if containment_existed:

            shutil.copy2(
                backup,
                CONTAINMENT_FILE
            )

        elif CONTAINMENT_FILE.exists():

            CONTAINMENT_FILE.unlink()

        ok(
            "Estado de contención restaurado"
        )

    except Exception as error:

        fail(
            (
                "No fue posible restaurar "
                f"contención: {error}"
            )
        )


    # Restaurar estado de integridad.

    try:

        backup = (
            temporary_path
            / "integrity_state.json"
        )

        if integrity_existed:

            shutil.copy2(
                backup,
                INTEGRITY_FILE
            )

        elif INTEGRITY_FILE.exists():

            INTEGRITY_FILE.unlink()

        ok(
            "Estado de integridad restaurado"
        )

    except Exception as error:

        fail(
            (
                "No fue posible restaurar "
                f"integridad: {error}"
            )
        )


    # Borrar directorio temporal.

    try:

        shutil.rmtree(
            temporary_path,
            ignore_errors=True
        )

        ok(
            "Backup temporal eliminado"
        )

    except Exception as error:

        fail(
            (
                "No fue posible limpiar "
                f"backup temporal: {error}"
            )
        )


# ==========================================================
# RESULTADO
# ==========================================================

print()
print("=" * 72)

if errors:

    print(
        (
            "RESULTADO: E2E TEST "
            f"CON {len(errors)} ERROR(ES)"
        )
    )

    print()

    for error in errors:

        print(
            f" - {error}"
        )

    print("=" * 72)
    print()

    sys.exit(1)


print(
    "RESULTADO: CYBERRANGECORE "
    "E2E ACCEPTANCE TEST APROBADO"
)

print("=" * 72)
print()

sys.exit(0)
