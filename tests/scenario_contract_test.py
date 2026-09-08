import sys

from copy import deepcopy
from pathlib import Path


PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT)
    )


from core.scenario_loader import (
    load_scenario,
)

from core.scenario_validator import (
    validate_scenario,
    assert_scenario_valid,
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


def expect_error(
    label: str,
    scenario: dict,
    expected_fragment: str
) -> None:

    errors = validate_scenario(
        scenario
    )

    found = any(
        expected_fragment
        in error
        for error in errors
    )

    check(
        found,
        label
    )

    if not found:

        print(
            "       Errores obtenidos:"
        )

        for error in errors:
            print(
                f"       - {error}"
            )


print()
print(
    "=" * 68
)
print(
    " CYBERRANGECORE - SCENARIO CONTRACT NEGATIVE TEST"
)
print(
    "=" * 68
)
print()


# ==========================================================
# ESCENARIOS BASE
# ==========================================================

cr001 = load_scenario(
    "CR-001"
)

cr002 = load_scenario(
    "CR-002"
)


print(
    "1. ESCENARIOS VÁLIDOS"
)
print(
    "-" * 68
)

check(
    not validate_scenario(
        cr001
    ),
    "CR-001 válido es aceptado"
)

check(
    not validate_scenario(
        cr002
    ),
    "CR-002 válido es aceptado"
)


# ==========================================================
# ID DUPLICADO
# ==========================================================

print()
print(
    "2. IDENTIFICADORES"
)
print(
    "-" * 68
)

scenario = deepcopy(
    cr001
)

first_id = (
    scenario["injects"][0]["id"]
)

scenario["injects"][1]["id"] = (
    first_id
)

expect_error(
    "ID duplicado es rechazado",
    scenario,
    f"id duplicado {first_id}"
)


# ==========================================================
# REFERENCIA A GATE INEXISTENTE
# ==========================================================

scenario = deepcopy(
    cr001
)

conditional_item = next(
    item
    for item in scenario["injects"]
    if item.get("condition")
)

conditional_item[
    "condition"
][
    "gate_id"
] = "GATE-999"

expect_error(
    "Referencia a GATE inexistente es rechazada",
    scenario,
    "referencia GATE-999, que no existe"
)


# ==========================================================
# ROL NO DECLARADO
# ==========================================================

print()
print(
    "3. ROLES Y GATES"
)
print(
    "-" * 68
)

scenario = deepcopy(
    cr001
)

gate = next(
    item
    for item in scenario["injects"]
    if item.get("type") == "GATE"
)

gate[
    "role_required"
] = "INVALID_ROLE"

expect_error(
    "Rol no declarado es rechazado",
    scenario,
    "requiere rol INVALID_ROLE"
)


# ==========================================================
# OPCIÓN DE GATE INEXISTENTE
# ==========================================================

scenario = deepcopy(
    cr001
)

conditional_item = next(
    item
    for item in scenario["injects"]
    if item.get("condition")
)

conditional_item[
    "condition"
][
    "option"
] = "INVALID_OPTION"

expect_error(
    "Opción de rama inexistente es rechazada",
    scenario,
    "esa opción no existe"
)


# ==========================================================
# DETECTOR NO SOPORTADO
# ==========================================================

print()
print(
    "4. TELEMETRÍA"
)
print(
    "-" * 68
)

scenario = deepcopy(
    cr001
)

telemetry_item = next(
    item
    for item in scenario["injects"]
    if item.get(
        "telemetry_condition"
    )
)

telemetry_item[
    "telemetry_condition"
][
    "detector"
] = "UNKNOWN_DETECTOR"

expect_error(
    "Detector no soportado es rechazado",
    scenario,
    (
        "detector no soportado: "
        "UNKNOWN_DETECTOR"
    )
)


# ==========================================================
# RELEASE_AFTER INVÁLIDO
# ==========================================================

scenario = deepcopy(
    cr001
)

release_item = next(
    item
    for item in scenario["injects"]
    if item.get(
        "release_after"
    )
)

release_item[
    "release_after"
][
    "inject_id"
] = "INJ-999"

expect_error(
    "Dependencia inexistente es rechazada",
    scenario,
    "depende de INJ-999, que no existe"
)


# ==========================================================
# RESET ACTION NO SOPORTADA
# ==========================================================

print()
print(
    "5. RUNTIME"
)
print(
    "-" * 68
)

scenario = deepcopy(
    cr001
)

scenario[
    "runtime"
][
    "reset_actions"
] = [
    "RESET_DOES_NOT_EXIST"
]

expect_error(
    "Reset action desconocida es rechazada",
    scenario,
    (
        "acción de reinicio no soportada: "
        "RESET_DOES_NOT_EXIST"
    )
)


# ==========================================================
# RUNTIME MAL FORMADO
# ==========================================================

scenario = deepcopy(
    cr001
)

scenario[
    "runtime"
] = []

expect_error(
    "Runtime mal formado es rechazado",
    scenario,
    "runtime debe ser un diccionario"
)


# ==========================================================
# ACCIÓN TÉCNICA NO SOPORTADA
# ==========================================================

print()
print(
    "6. ACCIONES TÉCNICAS"
)
print(
    "-" * 68
)

scenario = deepcopy(
    cr001
)

scenario[
    "technical_actions"
][
    "GATE-002"
] = "UNKNOWN_ACTION"

expect_error(
    "Acción técnica desconocida es rechazada",
    scenario,
    (
        "acción técnica no soportada: "
        "UNKNOWN_ACTION"
    )
)


# ==========================================================
# ACCIÓN TÉCNICA SOBRE GATE INEXISTENTE
# ==========================================================

scenario = deepcopy(
    cr001
)

scenario[
    "technical_actions"
] = {
    "GATE-999": (
        "CONTAINMENT_RESPONSE"
    )
}

expect_error(
    (
        "Acción técnica sobre GATE "
        "inexistente es rechazada"
    ),
    scenario,
    (
        "technical_actions referencia "
        "GATE-999, que no existe"
    )
)


# ==========================================================
# ASSERT ESTRICTO
# ==========================================================

print()
print(
    "7. RECHAZO ESTRICTO"
)
print(
    "-" * 68
)

scenario = deepcopy(
    cr002
)

scenario[
    "name"
] = ""

try:

    assert_scenario_valid(
        scenario
    )

except ValueError:

    ok(
        (
            "assert_scenario_valid bloquea "
            "escenario inválido"
        )
    )

else:

    fail(
        (
            "assert_scenario_valid permitió "
            "un escenario inválido"
        )
    )


# ==========================================================
# RESULTADO
# ==========================================================

print()
print(
    "=" * 68
)

if failed:

    print(
        (
            "RESULTADO: SCENARIO CONTRACT TEST "
            f"FALLÓ ({failed} errores)"
        )
    )

    print(
        "=" * 68
    )

    sys.exit(
        1
    )


print(
    (
        "RESULTADO: CYBERRANGECORE SCENARIO "
        "CONTRACT TEST APROBADO"
    )
)

print(
    (
        f"Pruebas aprobadas: {passed}"
    )
)

print(
    "=" * 68
)
