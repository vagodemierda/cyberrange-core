from pathlib import Path
import sys


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


from core.main import app
from core.scenario_loader import (
    list_scenarios,
    load_scenario,
)

from core.scenario_validator import (
    validate_scenario,
)

def ok(message):
    print(f"[OK]   {message}")


def fail(message):
    print(f"[FAIL] {message}")


errors = []


def check(condition, message):
    if condition:
        ok(message)

    else:
        fail(message)
        errors.append(message)


print()
print("=" * 64)
print(" CYBERRANGECORE - SMOKE TEST")
print("=" * 64)
print()


# ==========================================================
# 1. ARCHIVOS ESENCIALES
# ==========================================================

print("1. ARCHIVOS ESENCIALES")

required_files = [
    "core/main.py",
    "core/db.py",
    "core/models.py",
    "core/telemetry.py",
    "core/scenario_loader.py",
    "core/templates/home.html",
    "core/templates/scenario.html",
    "core/templates/session_new.html",
    "core/templates/session_view.html",
    "core/templates/gate.html",
    "core/templates/report.html",
    "core/static/styles.css",
    "target_app/app.py",
    "target_app/init_db.py",
    "scenarios/CR-001.yaml",
    "scenarios/CR-002.yaml",
]

for relative_path in required_files:

    path = PROJECT_ROOT / relative_path

    check(
        path.exists(),
        f"Existe {relative_path}"
    )


# ==========================================================
# 2. ESCENARIOS
# ==========================================================

print()
print("2. ESCENARIOS")

scenarios = list_scenarios()

scenario_ids = {
    scenario["id"]
    for scenario in scenarios
}

check(
    "CR-001" in scenario_ids,
    "CR-001 disponible"
)

check(
    "CR-002" in scenario_ids,
    "CR-002 disponible"
)


for scenario_id in sorted(scenario_ids):

    scenario = load_scenario(
        scenario_id
    )

    validation_errors = (
        validate_scenario(
            scenario
        )
    )

    check(
        not validation_errors,
        (
            f"{scenario_id}: "
            "contrato de escenario válido"
        )
    )

    if validation_errors:

        for validation_error in (
            validation_errors
        ):

            fail(
                (
                    f"{scenario_id}: "
                    f"{validation_error}"
                )
            )

    injects = scenario.get(
        "injects",
        []
    )

    ids = [
        item.get("id")
        for item in injects
    ]

    check(
        len(ids) == len(set(ids)),
        f"{scenario_id}: IDs internos únicos"
    )

    check(
        bool(scenario.get("name")),
        f"{scenario_id}: nombre configurado"
    )

    check(
        bool(scenario.get("roles")),
        f"{scenario_id}: roles configurados"
    )

    check(
        bool(scenario.get("metrics")),
        f"{scenario_id}: métricas configuradas"
    )

    gates = [
        item
        for item in injects
        if item.get("type") == "GATE"
    ]

    gate_ids = {
        gate.get("id")
        for gate in gates
    }

    for required_gate in {
        "GATE-000",
        "GATE-001",
        "GATE-002",
    }:

        check(
            required_gate in gate_ids,
            (
                f"{scenario_id}: "
                f"{required_gate} presente"
            )
        )

    # ------------------------------------------------------
    # REFERENCIAS INTERNAS
    # ------------------------------------------------------

    for item in injects:

        condition = item.get(
            "condition"
        )

        if condition:

            required_gate = condition.get(
                "gate_id"
            )

            check(
                required_gate in ids,
                (
                    f"{scenario_id}: "
                    f"{item.get('id')} referencia "
                    f"{required_gate}"
                )
            )

        release_after = item.get(
            "release_after"
        )

        if release_after:

            source_id = release_after.get(
                "inject_id"
            )

            check(
                source_id in ids,
                (
                    f"{scenario_id}: "
                    f"{item.get('id')} depende de "
                    f"{source_id}"
                )
            )


# ==========================================================
# 3. RUTAS FASTAPI
# ==========================================================

print()
print("3. RUTAS FASTAPI")

routes = {}

for route in app.routes:

    path = getattr(
        route,
        "path",
        None
    )

    methods = getattr(
        route,
        "methods",
        set()
    )

    if path:
        routes.setdefault(
            path,
            set()
        ).update(
            methods or set()
        )


required_routes = [
    (
        "/",
        "GET"
    ),
    (
        "/scenario/{scenario_id}",
        "GET"
    ),
    (
        "/session/new",
        "GET"
    ),
    (
        "/session/new",
        "POST"
    ),
    (
        "/session/{session_id}",
        "GET"
    ),
    (
        "/session/{session_id}/gate/{gate_id}",
        "GET"
    ),
    (
        "/session/{session_id}/gate/{gate_id}",
        "POST"
    ),
    (
        "/session/{session_id}/finish",
        "POST"
    ),
    (
        "/session/{session_id}/report",
        "GET"
    ),
]


for path, method in required_routes:

    check(
        (
            path in routes
            and method in routes[path]
        ),
        f"Ruta {method} {path}"
    )


# ==========================================================
# 4. STATIC
# ==========================================================

print()
print("4. INTERFAZ")

check(
    "/static" in routes,
    "Ruta /static registrada"
)


# ==========================================================
# RESULTADO
# ==========================================================

print()
print("=" * 64)

if errors:

    print(
        f"RESULTADO: {len(errors)} ERROR(ES)"
    )

    print()

    for error in errors:
        print(
            f" - {error}"
        )

    print("=" * 64)

    sys.exit(1)


print("RESULTADO: CYBERRANGECORE SMOKE TEST APROBADO")
print("=" * 64)
print()

sys.exit(0)
