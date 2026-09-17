import time
import json

from core.actions import (
    apply_containment_action,
    apply_integrity_action,
    execute_gate_action,
    reset_scenario_runtime,
)

from core.telemetry import (
    run_detector,
)

from html import escape
from fastapi import FastAPI, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from core.scenario_loader import list_scenarios, load_scenario
from core.db import SessionLocal
from core.models import SessionRun, Decision, InjectRelease

app = FastAPI(
    title="CyberRangeCore"
)

app.mount(
    "/static",
    StaticFiles(directory="core/static"),
    name="static"
)

templates = Jinja2Templates(
    directory="core/templates"
)


def now() -> float:
    return time.time()


def compute_elapsed_min(started_ts: float) -> int:
    return int((now() - started_ts) / 60)

def score_session(db, session_id: int) -> dict:
    session = db.get(SessionRun, session_id)

    if not session:
        return {
            "total": 0,
            "metrics": {
                "TTD_min": None,
                "TTE_min": None,
                "TTC_min": None
            },
            "decisions": [],
            "breakdown": [],
            "level": "N/A"
        }

    # --------------------------------------------------
    # CONFIGURACIÓN DEL ESCENARIO
    # --------------------------------------------------

    scenario = load_scenario(session.scenario_id)
    evaluation = scenario.get("evaluation", {})

    delay_penalty_per_min = float(
        evaluation.get("delay_penalty_per_min", 0)
    )

    expected_response = evaluation.get(
        "expected_response_min",
        {}
    )

    weights = evaluation.get(
        "weights",
        {}
    )

    performance_levels = evaluation.get(
        "performance_levels",
        []
    )

    # --------------------------------------------------
    # DECISIONES REGISTRADAS
    # --------------------------------------------------

    decisions = (
        db.query(Decision)
        .filter(Decision.session_id == session_id)
        .order_by(Decision.decided_ts.asc())
        .all()
    )

    decisions_by_gate = {
        decision.gate_id: decision
        for decision in decisions
    }

    # --------------------------------------------------
    # INSTANTES REALES DE LIBERACIÓN
    # --------------------------------------------------

    releases = (
        db.query(InjectRelease)
        .filter(InjectRelease.session_id == session_id)
        .all()
    )

    releases_by_inject = {
        release.inject_id: release
        for release in releases
    }

    # --------------------------------------------------
    # MÉTRICAS TEMPORALES
    # --------------------------------------------------

    metrics = {
        "TTD_min": None,
        "TTE_min": None,
        "TTC_min": None
    }

    gate_000 = decisions_by_gate.get("GATE-000")
    gate_001 = decisions_by_gate.get("GATE-001")
    gate_002 = decisions_by_gate.get("GATE-002")

    inj_001_release = releases_by_inject.get("INJ-001")
    gate_001_release = releases_by_inject.get("GATE-001")
    gate_002_release = releases_by_inject.get("GATE-002")

    # TTD:
    # desde que la alerta técnica se hace visible
    # hasta que el SOC reconoce/clasifica el incidente.
    if gate_000 and inj_001_release:
        metrics["TTD_min"] = round(
            (
                gate_000.decided_ts
                - inj_001_release.released_ts
            ) / 60,
            2
        )

    # TTE:
    # desde que la decisión de escalamiento está disponible
    # hasta que el SOC toma la decisión de escalar.
    if gate_001 and gate_001_release:
        metrics["TTE_min"] = round(
            (
                gate_001.decided_ts
                - gate_001_release.released_ts
            ) / 60,
            2
        )

    # TTC:
    # desde que la decisión de contención está disponible
    # hasta que el IR Lead decide la contención.
    if gate_002 and gate_002_release:
        metrics["TTC_min"] = round(
            (
                gate_002.decided_ts
                - gate_002_release.released_ts
            ) / 60,
            2
        )

    # --------------------------------------------------
    # CÁLCULO DEL PUNTAJE
    # --------------------------------------------------

    total_score = 0.0
    breakdown = []

    for decision in decisions:

        gate_id = decision.gate_id

        base_score = float(
            decision.option_score
        )

        weight = float(
            weights.get(gate_id, 1.0)
        )

        weighted_score = (
            base_score * weight
        )

        expected_min = float(
            expected_response.get(
                gate_id,
                0
            )
        )

        # Buscar el instante real en que ese gate
        # quedó disponible para el participante.
        gate_release = releases_by_inject.get(
            gate_id
        )

        response_min = None
        delay_min = 0.0
        delay_penalty = 0.0

        if gate_release:

            response_min = round(
                (
                    decision.decided_ts
                    - gate_release.released_ts
                ) / 60,
                2
            )

            delay_min = round(
                max(
                    0.0,
                    response_min - expected_min
                ),
                2
            )

            delay_penalty = round(
                delay_min
                * delay_penalty_per_min,
                2
            )

        final_score = round(
            weighted_score - delay_penalty,
            2
        )

        total_score += final_score

        breakdown.append({
            "gate_id": gate_id,
            "role": decision.role,
            "option_key": decision.option_key,
            "base_score": base_score,
            "weight": weight,
            "weighted_score": round(
                weighted_score,
                2
            ),

            # Se mantiene este nombre para no romper
            # las plantillas actuales.
            "elapsed_min": response_min,

            "response_min": response_min,
            "expected_min": expected_min,
            "delay_min": delay_min,
            "delay_penalty": delay_penalty,
            "final_score": final_score
        })

    total_score = round(
        total_score,
        2
    )

    # --------------------------------------------------
    # NIVEL DE DESEMPEÑO
    # --------------------------------------------------

    # --------------------------------------------------
    # NIVEL DE DESEMPEÑO
    # --------------------------------------------------

    if not decisions:
        performance_level = "Pendiente"

    elif session.status != "FINISHED":
        performance_level = "En progreso"

    else:
        performance_level = "N/A"

        for level in performance_levels:

            min_score = float(
                level.get(
                    "min_score",
                    -999999
                )
            )

            max_score = float(
                level.get(
                    "max_score",
                    999999
                )
            )

            if (
                min_score
                <= total_score
                <= max_score
            ):

                performance_level = level.get(
                    "name",
                    "N/A"
                )

                break

    return {
        "total": total_score,
        "metrics": metrics,
        "decisions": decisions,
        "breakdown": breakdown,
        "level": performance_level
    }

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    scenarios = list_scenarios()
    return templates.TemplateResponse("home.html", {"request": request, "scenarios": scenarios})


@app.get("/scenario/{scenario_id}", response_class=HTMLResponse)
def view_scenario(request: Request, scenario_id: str):
    scenario = load_scenario(scenario_id)
    return templates.TemplateResponse("scenario.html", {"request": request, "scenario": scenario})


@app.get("/session/new", response_class=HTMLResponse)
def session_new(request: Request):
    scenarios = list_scenarios()
    return templates.TemplateResponse("session_new.html", {"request": request, "scenarios": scenarios})


@app.post("/session/new")
def session_create(
    scenario_id: str = Form(...),
    soc_name: str = Form(...),
    ir_name: str = Form(...)
):
    db = SessionLocal()
    try:
        roles = {"SOC_ANALYST": soc_name, "IR_LEAD": ir_name}
        s = SessionRun(
            scenario_id=scenario_id,
            started_ts=now(),
            status="RUNNING",
            roles_json=json.dumps(roles, ensure_ascii=False),
        )

        db.add(s)
        db.commit()
        db.refresh(s)

        # --------------------------------------------------
        # REINICIO CONFIGURABLE DEL LABORATORIO
        # --------------------------------------------------

        scenario = load_scenario(
            scenario_id
        )

        reset_ok, reset_reason = (
            reset_scenario_runtime(
                scenario,
                s.id
            )
        )

        if not reset_ok:
            return HTMLResponse(
                reset_reason,
                status_code=500
            )


        return RedirectResponse(
            url=f"/session/{s.id}",
            status_code=303
        )

    finally:
        db.close()


@app.get("/session/{session_id}", response_class=HTMLResponse)
def session_view(request: Request, session_id: int):
    db = SessionLocal()
    try:
        session = db.query(SessionRun).get(session_id)
        if not session:
            return HTMLResponse("Sesión no encontrada", status_code=404)

        scenario = load_scenario(session.scenario_id)
        roles = json.loads(session.roles_json)
        if (
            session.status == "FINISHED"
            and session.finished_ts is not None
        ):
            elapsed_min = int(
                (
                    session.finished_ts
                    - session.started_ts
                ) / 60
            )

        else:
            elapsed_min = compute_elapsed_min(
                session.started_ts
            )

        decisions = db.query(Decision).filter(Decision.session_id == session_id).all()
        decisions_by_gate = {d.gate_id: d for d in decisions}

        releases = (
            db.query(InjectRelease)
            .filter(InjectRelease.session_id == session_id)
            .all()
        )

        releases_by_inject = {
            release.inject_id: release
            for release in releases
        }

        timeline = []

        for inj in scenario.get("injects", []):
            item = dict(inj)

            item_t = int(item.get("t_min", 0))
            item["is_released"] = (elapsed_min >= item_t)
            item["remaining_min"] = max(0, item_t - elapsed_min)
            item["display_t_min"] = item_t

            inject_id = item.get("id")

            release = releases_by_inject.get(inject_id)

            # --------------------------------------------------
            # EVENTO YA LIBERADO ANTERIORMENTE
            # --------------------------------------------------
            # Si el inject ya fue liberado en esta sesión,
            # se conserva como parte permanente del historial.

            if release:

                item["released_ts"] = release.released_ts

                item["display_t_min"] = round(
                    (
                        release.released_ts
                        - session.started_ts
                    ) / 60,
                    2
                )

                if release.telemetry_json:

                    try:
                        item["telemetry"] = json.loads(
                            release.telemetry_json
                        )

                    except (
                        json.JSONDecodeError,
                        TypeError
                    ):
                        pass

            else:

                # --------------------------------------------------
                # CONTROL TEMPORAL
                # --------------------------------------------------

                release_after = item.get("release_after")

                if release_after:

                    source_inject_id = release_after.get(
                        "inject_id"
                    )

                    delay_min = float(
                        release_after.get(
                            "delay_min",
                            0
                        )
                    )

                    source_release = releases_by_inject.get(
                        source_inject_id
                    )

                    # El evento de referencia todavía
                    # no ha sido liberado.
                    if not source_release:
                        continue

                    available_ts = (
                        source_release.released_ts
                        + (delay_min * 60)
                    )

                    current_ts = now()

                    item["is_released"] = (
                        current_ts >= available_ts
                    )

                    item["remaining_min"] = round(
                        max(
                            0.0,
                            (
                                available_ts
                                - current_ts
                            ) / 60
                        ),
                        2
                    )

                else:

                    item["is_released"] = (
                        elapsed_min >= item_t
                    )

                    item["remaining_min"] = max(
                        0,
                        item_t - elapsed_min
                    )

                if not item["is_released"]:
                    continue

                # --------------------------------------------------
                # CONDICIONES BASADAS EN TELEMETRÍA
                # --------------------------------------------------

                telemetry_condition = item.get(
                    "telemetry_condition"
                )

                if telemetry_condition:

                    detector = telemetry_condition.get(
                        "detector"
                    )

                    expected_status = (
                        telemetry_condition.get(
                            "expected_status"
                        )
                    )

                    telemetry_result = (
                        run_detector(
                            detector,
                            telemetry_condition
                        )
                    )

                    if telemetry_result is None:
                        continue

                    # ----------------------------------------------
                    # VALIDACIÓN DEL ESTADO TÉCNICO
                    # ----------------------------------------------

                    if (
                        not telemetry_result
                        or telemetry_result.get("status")
                        != expected_status
                    ):
                        continue

                    # La evidencia que provocó la liberación
                    # queda asociada al inject o gate.

                    item["telemetry"] = (
                        telemetry_result
                    )

                # --------------------------------------------------
                # CONTROL DE RAMIFICACIÓN
                # --------------------------------------------------

                condition = item.get("condition")

                if condition:

                    required_gate = condition.get(
                        "gate_id"
                    )

                    required_options = condition.get(
                        "options"
                    )

                    if required_options is None:

                        required_option = condition.get(
                            "option"
                        )

                        required_options = (
                            [required_option]
                            if required_option is not None
                            else []
                        )

                    previous_decision = decisions_by_gate.get(
                        required_gate
                    )

                    if not previous_decision:
                        continue

                    if (
                        previous_decision.option_key
                        not in required_options
                    ):
                        continue

                # --------------------------------------------------
                # REGISTRO DE LIBERACIÓN DEL INJECT
                # --------------------------------------------------

                if session.status == "RUNNING":

                    telemetry_snapshot = None

                    if item.get("telemetry") is not None:

                        telemetry_snapshot = json.dumps(
                            item["telemetry"],
                            ensure_ascii=False
                        )

                    release = InjectRelease(
                        session_id=session_id,
                        inject_id=inject_id,
                        released_ts=now(),
                        telemetry_json=telemetry_snapshot
                    )

                    db.add(release)
                    db.commit()
                    db.refresh(release)

                    releases_by_inject[inject_id] = release

                    item["released_ts"] = release.released_ts
                    item["display_t_min"] = round(
                        (
                            release.released_ts
                            - session.started_ts
                        ) / 60,
                        2
                    )

            # --------------------------------------------------
            # ESTADO DE LOS GATES
            # --------------------------------------------------
            if item.get("type") == "GATE":
                gate_id = item.get("id")

                if gate_id in decisions_by_gate:
                    item["gate_status"] = "DONE"
                    item["decision"] = decisions_by_gate[gate_id]

                else:
                    item["gate_status"] = "PENDING"

            timeline.append(item)

        timeline.sort(
            key=lambda item: item.get(
                "display_t_min",
                item.get("t_min", 0)
            )
        )

        score = score_session(db, session_id)

        return templates.TemplateResponse(
            "session_view.html",
            {
                "request": request,
                "session": session,
                "roles": roles,
                "elapsed_min": elapsed_min,
                "timeline": timeline,
                "score": score,
            },
        )
    finally:
        db.close()

def ensure_gate_available(
    db,
    session,
    gate: dict
) -> tuple[bool, str]:

    gate_id = gate.get("id")

    # --------------------------------------------------
    # ESTADO DE LA SESIÓN
    # --------------------------------------------------

    if session.status != "RUNNING":
        return False, "La sesión está finalizada."

    # --------------------------------------------------
    # SI EL GATE YA FUE LIBERADO
    # --------------------------------------------------

    existing_release = (
        db.query(InjectRelease)
        .filter(
            InjectRelease.session_id == session.id,
            InjectRelease.inject_id == gate_id
        )
        .first()
    )

    if existing_release:
        return True, ""

    # --------------------------------------------------
    # DEPENDENCIA DE UNA DECISIÓN ANTERIOR
    # --------------------------------------------------

    condition = gate.get("condition")

    if condition:

        required_gate = condition.get(
            "gate_id"
        )

        required_options = condition.get(
            "options"
        )

        if required_options is None:

            required_option = condition.get(
                "option"
            )

            required_options = (
                [required_option]
                if required_option is not None
                else []
            )

        previous_decision = (
            db.query(Decision)
            .filter(
                Decision.session_id == session.id,
                Decision.gate_id == required_gate
            )
            .first()
        )

        if not previous_decision:
            return (
                False,
                "Gate bloqueado: falta una decisión previa."
            )

        if (
            previous_decision.option_key
            not in required_options
        ):
            return (
                False,
                "Gate no habilitado para la rama seleccionada."
            )

    # --------------------------------------------------
    # CONTROL TEMPORAL RELATIVO O ABSOLUTO
    # --------------------------------------------------

    release_after = gate.get(
        "release_after"
    )

    if release_after:

        source_inject_id = release_after.get(
            "inject_id"
        )

        delay_min = float(
            release_after.get(
                "delay_min",
                0
            )
        )

        source_release = (
            db.query(InjectRelease)
            .filter(
                InjectRelease.session_id == session.id,
                InjectRelease.inject_id == source_inject_id
            )
            .first()
        )

        if not source_release:
            return (
                False,
                f"Gate bloqueado: todavía no se ha liberado "
                f"{source_inject_id}."
            )

        available_ts = (
            source_release.released_ts
            + (delay_min * 60)
        )

        current_ts = now()

        if current_ts < available_ts:

            remaining_min = round(
                (
                    available_ts
                    - current_ts
                ) / 60,
                2
            )

            return (
                False,
                f"Gate bloqueado. Faltan "
                f"{remaining_min} min."
            )

    else:

        elapsed_min = (
            now()
            - session.started_ts
        ) / 60

        gate_t = float(
            gate.get(
                "t_min",
                0
            )
        )

        if elapsed_min < gate_t:

            remaining_min = round(
                gate_t - elapsed_min,
                2
            )

            return (
                False,
                f"Gate bloqueado. Faltan "
                f"{remaining_min} min."
            )

    # --------------------------------------------------
    # CONDICIÓN DE TELEMETRÍA
    # --------------------------------------------------

    telemetry_result = None

    telemetry_condition = gate.get(
        "telemetry_condition"
    )

    if telemetry_condition:

        detector = telemetry_condition.get(
            "detector"
        )

        expected_status = telemetry_condition.get(
            "expected_status"
        )

        telemetry_result = run_detector(
            detector,
            telemetry_condition
        )

        if telemetry_result is None:
            return (
                False,
                "Detector de telemetría no reconocido."
            )

        if (
            telemetry_result.get("status")
            != expected_status
        ):
            return (
                False,
                "Gate bloqueado: la condición técnica "
                "todavía no se cumple."
            )

    # --------------------------------------------------
    # REGISTRAR LIBERACIÓN DEL GATE
    # --------------------------------------------------

    telemetry_snapshot = None

    if telemetry_result is not None:

        telemetry_snapshot = json.dumps(
            telemetry_result,
            ensure_ascii=False
        )

    release = InjectRelease(
        session_id=session.id,
        inject_id=gate_id,
        released_ts=now(),
        telemetry_json=telemetry_snapshot
    )

    db.add(release)
    db.commit()

    return True, ""

@app.get("/session/{session_id}/gate/{gate_id}", response_class=HTMLResponse)
def gate_view(request: Request, session_id: int, gate_id: str):
    db = SessionLocal()
    try:
        session = db.query(SessionRun).get(session_id)
        if not session:
            return HTMLResponse("Sesión no encontrada", status_code=404)

        existing = db.query(Decision).filter(
            Decision.session_id == session_id,
            Decision.gate_id == gate_id
        ).first()
        if existing:
            return RedirectResponse(url=f"/session/{session_id}", status_code=303)

        scenario = load_scenario(session.scenario_id)
        gate = next((x for x in scenario.get("injects", []) if x.get("id") == gate_id and x.get("type") == "GATE"), None)
        if not gate:
            return HTMLResponse("Gate no encontrado", status_code=404)

        # --------------------------------------------------
        # VALIDACIÓN DE DISPONIBILIDAD DEL GATE
        # --------------------------------------------------

        available, reason = ensure_gate_available(
            db,
            session,
            gate
        )

        if not available:
            return HTMLResponse(
                reason,
                status_code=403
            )

        return templates.TemplateResponse("gate.html", {"request": request, "session_id": session_id, "gate": gate})
    finally:
        db.close()


@app.post("/session/{session_id}/gate/{gate_id}")
def gate_submit(
    session_id: int,
    gate_id: str,
    option_key: str = Form(...),
    justification: str = Form("")
):
    db = SessionLocal()

    try:
        session = db.query(SessionRun).get(session_id)

        if not session:
            return HTMLResponse(
                "Sesión no encontrada",
                status_code=404
            )

        # --------------------------------------------------
        # IMPEDIR DECISIONES EN SESIONES FINALIZADAS
        # --------------------------------------------------

        if session.status != "RUNNING":
            return HTMLResponse(
                "La sesión está finalizada.",
                status_code=403
            )

        # --------------------------------------------------
        # IMPEDIR DECISIONES DUPLICADAS
        # --------------------------------------------------

        existing = db.query(Decision).filter(
            Decision.session_id == session_id,
            Decision.gate_id == gate_id
        ).first()

        if existing:
            return HTMLResponse(
                "Esta decisión ya fue registrada.",
                status_code=409
            )

        scenario = load_scenario(session.scenario_id)

        gate = next(
            (
                x
                for x in scenario.get("injects", [])
                if x.get("id") == gate_id
                and x.get("type") == "GATE"
            ),
            None
        )

        if not gate:
            return HTMLResponse(
                "Gate no encontrado",
                status_code=404
            )

        # --------------------------------------------------
        # VALIDACIÓN DE DISPONIBILIDAD DEL GATE
        # --------------------------------------------------

        available, reason = ensure_gate_available(
            db,
            session,
            gate
        )

        if not available:
            return HTMLResponse(
                reason,
                status_code=403
            )

        # --------------------------------------------------
        # VALIDACIÓN DE LA OPCIÓN SELECCIONADA
        # --------------------------------------------------

        role_required = gate.get("role_required")

        option = next(
            (
                o
                for o in gate.get("options", [])
                if o.get("key") == option_key
            ),
            None
        )

        if not option:
            return HTMLResponse(
                "Opción inválida",
                status_code=400
            )

        # --------------------------------------------------
        # JUSTIFICACIÓN OBLIGATORIA
        # --------------------------------------------------

        clean_justification = justification.strip()

        if not clean_justification:
            return HTMLResponse(
                "La justificación de la decisión es obligatoria.",
                status_code=400
            )

        # --------------------------------------------------
        # CONSECUENCIA TÉCNICA CONFIGURABLE
        # --------------------------------------------------

        action_ok, action_reason = (
            execute_gate_action(
                scenario,
                gate_id,
                db,
                session,
                option_key
            )
        )

        if not action_ok:
            return HTMLResponse(
                action_reason,
                status_code=500
            )

        # --------------------------------------------------
        # REGISTRO DE LA DECISIÓN
        # --------------------------------------------------

        decision = Decision(
            session_id=session_id,
            gate_id=gate_id,
            role=role_required,
            option_key=option_key,
            option_score=int(option.get("score", 0)),
            decided_ts=now(),
            justification=clean_justification
        )

        db.add(decision)
        db.commit()

        return RedirectResponse(
            url=f"/session/{session_id}",
            status_code=303
        )

    finally:
        db.close()


@app.post("/session/{session_id}/finish")

def session_finish(session_id: int):
    db = SessionLocal()

    try:
        session = db.query(SessionRun).get(session_id)

        if not session:
            return HTMLResponse(
                "Sesión no encontrada",
                status_code=404
            )

        if session.status == "FINISHED":
            return HTMLResponse(
                "La sesión ya fue finalizada.",
                status_code=409
            )

        session.status = "FINISHED"
        session.finished_ts = now()
        db.commit()

        return RedirectResponse(
            url=f"/session/{session_id}",
            status_code=303
        )

    finally:
        db.close()


@app.get(
    "/session/{session_id}/report",
    response_class=HTMLResponse
)
def session_report(
    request: Request,
    session_id: int
):
    db = SessionLocal()

    try:
        session = db.query(
            SessionRun
        ).get(
            session_id
        )

        if not session:
            return HTMLResponse(
                "Sesión no encontrada",
                status_code=404
            )

        scenario = load_scenario(
            session.scenario_id
        )

        score = score_session(
            db,
            session_id
        )

        # --------------------------------------------------
        # ROLES
        # --------------------------------------------------

        try:
            roles = json.loads(
                session.roles_json
                or "{}"
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):
            roles = {}

        # --------------------------------------------------
        # DECISIONES Y GATES
        # --------------------------------------------------

        decisions_by_gate = {
            decision.gate_id: decision
            for decision in score["decisions"]
        }

        gates_by_id = {
            item.get("id"): item
            for item in scenario.get(
                "injects",
                []
            )
            if item.get("type") == "GATE"
        }

        decision_details = []

        # --------------------------------------------------
        # DETALLE DE DECISIONES
        # --------------------------------------------------

        for item in score["breakdown"]:

            gate_id = item["gate_id"]

            decision = decisions_by_gate.get(
                gate_id
            )

            gate = gates_by_id.get(
                gate_id,
                {}
            )

            justification = (
                "Sin justificación registrada."
            )

            if (
                decision
                and decision.justification
            ):
                justification = (
                    decision.justification
                )

            selected_option = next(
                (
                    option
                    for option
                    in gate.get(
                        "options",
                        []
                    )
                    if option.get("key")
                    == item["option_key"]
                ),
                {}
            )

            outcome = selected_option.get(
                "outcome",
                (
                    "Sin consecuencia "
                    "descriptiva configurada."
                )
            )

            decision_details.append({
                "gate_id": gate_id,
                "role": item["role"],
                "option_key": item[
                    "option_key"
                ],
                "base_score": item[
                    "base_score"
                ],
                "weight": item[
                    "weight"
                ],
                "elapsed_min": item[
                    "elapsed_min"
                ],
                "expected_min": item[
                    "expected_min"
                ],
                "delay_min": item[
                    "delay_min"
                ],
                "delay_penalty": item[
                    "delay_penalty"
                ],
                "final_score": item[
                    "final_score"
                ],
                "justification": (
                    justification
                ),
                "outcome": outcome,
            })

        # --------------------------------------------------
        # ORIENTACIONES
        # --------------------------------------------------

        recommendations = []

        if not score["breakdown"]:

            recommendations.append(
                "No existe evidencia suficiente "
                "para generar orientaciones de "
                "desempeño."
            )

        else:

            for item in score["breakdown"]:

                gate_id = item["gate_id"]

                gate = gates_by_id.get(
                    gate_id,
                    {}
                )

                option_scores = [
                    int(
                        option.get(
                            "score",
                            0
                        )
                    )
                    for option
                    in gate.get(
                        "options",
                        []
                    )
                ]

                max_option_score = (
                    max(option_scores)
                    if option_scores
                    else item["base_score"]
                )

                if (
                    item["base_score"]
                    < max_option_score
                ):

                    recommendations.append(
                        f"{gate_id}: la alternativa "
                        "seleccionada no corresponde "
                        "a la opción con mayor "
                        "valoración configurada para "
                        "este punto de decisión. "
                        "Se recomienda revisar los "
                        "criterios técnicos y "
                        "estratégicos aplicables."
                    )

                if item["delay_min"] > 0:

                    recommendations.append(
                        f"{gate_id}: la decisión se "
                        f"tomó {item['delay_min']} "
                        "minuto(s) después del tiempo "
                        "objetivo. Se recomienda "
                        "reforzar la oportunidad de "
                        "respuesta y los mecanismos "
                        "de coordinación."
                    )

                else:

                    recommendations.append(
                        f"{gate_id}: la decisión fue "
                        "registrada dentro del tiempo "
                        "objetivo establecido para "
                        "el escenario."
                    )

            # ----------------------------------------------
            # ORIENTACIÓN GENERAL
            # ----------------------------------------------

            if score["level"] == "Bajo":

                recommendations.append(
                    "Resultado general: se recomienda "
                    "reforzar criterios de "
                    "priorización, oportunidad de "
                    "respuesta y ejecución coordinada "
                    "antes de repetir el escenario."
                )

            elif score["level"] == "Medio":

                recommendations.append(
                    "Resultado general: existe un "
                    "desempeño parcialmente "
                    "satisfactorio; se recomienda "
                    "consolidar la velocidad de "
                    "respuesta y la consistencia en "
                    "la toma de decisiones."
                )

            elif score["level"] == "Alto":

                recommendations.append(
                    "Resultado general: se evidencia "
                    "un desempeño favorable en las "
                    "decisiones evaluadas. Se "
                    "recomienda continuar con "
                    "escenarios de mayor complejidad."
                )

        # --------------------------------------------------
        # RENDER
        # --------------------------------------------------

        return templates.TemplateResponse(
            "report.html",
            {
                "request": request,
                "session": session,
                "scenario": scenario,
                "roles": roles,
                "score": score,
                "decision_details": (
                    decision_details
                ),
                "recommendations": (
                    recommendations
                ),
            }
        )

    finally:
        db.close()

