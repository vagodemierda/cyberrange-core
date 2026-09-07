from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from pathlib import Path
from datetime import datetime, timezone
import json
import sqlite3
from integrity_state import (
    read_integrity_state,
)

from range_state import (
    read_containment_state,
)


BASE_DIR = Path(__file__).resolve().parent

TEMPLATES_DIR = BASE_DIR / "templates"
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "events.jsonl"
DB_FILE = BASE_DIR / "data" / "portal.db"

LOG_DIR.mkdir(exist_ok=True)


app = FastAPI(
    title="Portal Académico Ficticio - CyberRange"
)

templates = Jinja2Templates(
    directory=str(TEMPLATES_DIR)
)


def register_event(
    request: Request,
    event_type: str,
    status: str,
    username: str = "",
    message: str = ""
):
    """
    Registra eventos técnicos del servicio objetivo
    en formato JSON Lines.
    """

    source_ip = "unknown"

    if request.client:
        source_ip = request.client.host

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "source_ip": source_ip,
        "method": request.method,
        "path": request.url.path,
        "username": username,
        "status": status,
        "message": message
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(
            json.dumps(event, ensure_ascii=False) + "\n"
        )


@app.get("/", response_class=HTMLResponse)
def home(request: Request):

    register_event(
        request=request,
        event_type="PAGE_VIEW",
        status="INFO",
        message="Acceso a la página de autenticación"
    )

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": None
        }
    )


@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):

    # --------------------------------------------------
    # ESTADO DE CONTENCIÓN DEL CYBER RANGE
    # --------------------------------------------------

    containment_state = (
        read_containment_state()
    )

    containment_mode = (
        containment_state.get(
            "mode",
            "NONE"
        )
    )

    source_ip = "unknown"

    if request.client:
        source_ip = request.client.host

    # --------------------------------------------------
    # CONTENCIÓN TOTAL
    # --------------------------------------------------

    if containment_mode == "ISOLATED":

        register_event(
            request=request,
            event_type="SERVICE_ISOLATED",
            status="BLOCKED",
            username=username,
            message=(
                "Intento de autenticación rechazado "
                "porque el servicio se encuentra "
                "aislado por una medida de contención."
            )
        )

        return HTMLResponse(
            (
                "<h1>Servicio temporalmente aislado</h1>"
                "<p>La autenticación fue deshabilitada "
                "como medida de contención del incidente."
                "</p>"
            ),
            status_code=503
        )

    # --------------------------------------------------
    # CONTENCIÓN PARCIAL
    # --------------------------------------------------

    blocked_ips = containment_state.get(
        "blocked_ips",
        []
    )

    if (
        containment_mode == "PARTIAL"
        and source_ip in blocked_ips
    ):

        register_event(
            request=request,
            event_type="CONTAINMENT_BLOCK",
            status="BLOCKED",
            username=username,
            message=(
                "Solicitud rechazada por medida "
                "de contención parcial. "
                f"IP bloqueada: {source_ip}"
            )
        )

        return HTMLResponse(
            (
                "<h1>Acceso bloqueado</h1>"
                "<p>La dirección IP origen fue "
                "bloqueada como medida de contención."
                "</p>"
            ),
            status_code=403
        )


    connection = sqlite3.connect(
        DB_FILE
    )

    cursor = connection.cursor()

    # --------------------------------------------------
    # CONSULTA DELIBERADAMENTE VULNERABLE
    # --------------------------------------------------
    # Esta construcción mediante concatenación de
    # entradas es intencional y existe únicamente
    # dentro del entorno experimental CyberRangeCore.
    vulnerable_query = (
        "SELECT id, username, role "
        "FROM users "
        f"WHERE username = '{username}' "
        f"AND password = '{password}'"
    )

    try:
        cursor.execute(
            vulnerable_query
        )

        user = cursor.fetchone()

    except sqlite3.Error as error:

        connection.close()

        register_event(
            request=request,
            event_type="LOGIN_QUERY_ERROR",
            status="ERROR",
            username=username,
            message=(
                "La consulta de autenticación produjo "
                f"un error SQL: {error}"
            )
        )

        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Error al procesar la autenticación."
            }
        )

    # --------------------------------------------------
    # VALIDACIÓN PARA IDENTIFICAR BYPASS
    # --------------------------------------------------
    # Esta segunda consulta utiliza parámetros seguros
    # únicamente para determinar si las credenciales
    # introducidas eran realmente válidas.
    legitimate_user = cursor.execute(
        """
        SELECT id, username, role
        FROM users
        WHERE username = ?
        AND password = ?
        """,
        (
            username,
            password
        )
    ).fetchone()

    connection.close()

    # --------------------------------------------------
    # AUTENTICACIÓN EXITOSA
    # --------------------------------------------------

    if user:

        user_id = user[0]
        authenticated_username = user[1]
        authenticated_role = user[2]

        # Si la consulta vulnerable permitió entrar,
        # pero las credenciales exactas no existen,
        # se considera un bypass de autenticación.
        if not legitimate_user:

            register_event(
                request=request,
                event_type="AUTH_BYPASS",
                status="CRITICAL",
                username=username,
                message=(
                    "Acceso no autorizado obtenido mediante "
                    "manipulación de la consulta de autenticación. "
                    f"Cuenta resultante: {authenticated_username}; "
                    f"rol: {authenticated_role}; "
                    f"id: {user_id}"
                )
            )

        else:

            register_event(
                request=request,
                event_type="LOGIN_SUCCESS",
                status="SUCCESS",
                username=authenticated_username,
                message=(
                    "Autenticación legítima correcta. "
                    f"Rol: {authenticated_role}"
                )
            )

        return RedirectResponse(
            url="/dashboard",
            status_code=303
        )

    # --------------------------------------------------
    # AUTENTICACIÓN FALLIDA
    # --------------------------------------------------

    register_event(
        request=request,
        event_type="LOGIN_FAILURE",
        status="WARNING",
        username=username,
        message="Intento de autenticación fallido"
    )

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": "Credenciales incorrectas."
        }
    )


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):

    register_event(
        request=request,
        event_type="PAGE_VIEW",
        status="INFO",
        username="estudiante",
        message="Acceso al panel académico ficticio"
    )

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "student": {
                "name": "Estudiante Demo",
                "program": "Programa Académico Ficticio",
                "period": "2026-II"
            }
        }
    )


@app.get("/health")
def health():

    return {
        "status": "ok",
        "service": "cyberrange-target"
    }
@app.get(
    "/records",
    response_class=HTMLResponse
)
def academic_records(
    request: Request
):

    connection = sqlite3.connect(
        DB_FILE
    )

    record = connection.execute(
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

    connection.close()

    if not record:
        return HTMLResponse(
            "Registro académico no encontrado",
            status_code=404
        )

    return HTMLResponse(
        f"""
        <h1>Registro académico</h1>

        <p><strong>ID:</strong> {record[0]}</p>
        <p><strong>Estudiante:</strong> {record[1]}</p>
        <p><strong>Curso:</strong> {record[2]}</p>
        <p><strong>Calificación:</strong> {record[3]}</p>
        <p><strong>Última actualización:</strong> {record[4]}</p>
        """
    )


@app.post(
    "/records/update",
    response_class=HTMLResponse
)
def update_academic_record(
    request: Request,
    record_id: int = Form(...),
    new_grade: float = Form(...)
):

    # --------------------------------------------------
    # ESTADO DE RESPUESTA DE INTEGRIDAD
    # --------------------------------------------------

    integrity_state = (
        read_integrity_state()
    )

    integrity_mode = (
        integrity_state.get(
            "mode",
            "NONE"
        )
    )

    # --------------------------------------------------
    # MÓDULO AISLADO
    # --------------------------------------------------

    if integrity_mode == "ISOLATED":

        register_event(
            request=request,
            event_type="RECORDS_ISOLATED",
            status="BLOCKED",
            username="unauthenticated",
            message=(
                "Intento de modificación rechazado "
                "porque el módulo académico se "
                "encuentra aislado."
            )
        )

        return HTMLResponse(
            (
                "<h1>Módulo temporalmente aislado</h1>"
                "<p>La edición de registros académicos "
                "fue deshabilitada como medida de "
                "respuesta al incidente.</p>"
            ),
            status_code=503
        )

    # --------------------------------------------------
    # REGISTRO RESTAURADO Y PROTEGIDO
    # --------------------------------------------------

    if integrity_mode == "PROTECTED":

        register_event(
            request=request,
            event_type="INTEGRITY_BLOCK",
            status="BLOCKED",
            username="unauthenticated",
            message=(
                "Intento de modificación no autorizada "
                "bloqueado después de restaurar y "
                "proteger el registro académico."
            )
        )

        return HTMLResponse(
            (
                "<h1>Modificación bloqueada</h1>"
                "<p>El registro académico se encuentra "
                "protegido después de la respuesta "
                "al incidente.</p>"
            ),
            status_code=403
        )


    connection = sqlite3.connect(
        DB_FILE
    )

    cursor = connection.cursor()

    record = cursor.execute(
        """
        SELECT
            id,
            student_code,
            course,
            grade,
            updated_by
        FROM academic_records
        WHERE id = ?
        """,
        (
            record_id,
        )
    ).fetchone()

    if not record:

        connection.close()

        return HTMLResponse(
            "Registro académico no encontrado",
            status_code=404
        )

    previous_grade = record[3]

    # --------------------------------------------------
    # CONTROL DE ACCESO DELIBERADAMENTE INSEGURO
    # --------------------------------------------------
    # El endpoint modifica información académica sin
    # comprobar autenticación ni autorización.
    # Esta debilidad existe únicamente dentro del
    # entorno experimental CyberRangeCore.

    cursor.execute(
        """
        UPDATE academic_records
        SET grade = ?,
            updated_by = ?
        WHERE id = ?
        """,
        (
            new_grade,
            "unauthenticated",
            record_id
        )
    )

    connection.commit()
    connection.close()

    register_event(
        request=request,
        event_type="DATA_TAMPERING",
        status="CRITICAL",
        username="unauthenticated",
        message=(
            "Modificación no autorizada de información "
            f"académica. Registro: {record_id}; "
            f"calificación anterior: {previous_grade}; "
            f"calificación nueva: {new_grade}"
        )
    )

    return HTMLResponse(
        (
            "<h1>Registro modificado</h1>"
            f"<p>Calificación anterior: {previous_grade}</p>"
            f"<p>Calificación nueva: {new_grade}</p>"
            '<p><a href="/records">Ver registro</a></p>'
        )
    )
