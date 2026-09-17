from typing import Any

from core.actions import (
    SUPPORTED_RESET_ACTIONS,
    SUPPORTED_GATE_ACTIONS,
)

from core.telemetry import (
    SUPPORTED_TELEMETRY_DETECTORS,
)


def validate_scenario(
    scenario: dict[str, Any]
) -> list[str]:

    errors = []

    # ======================================================
    # ESTRUCTURA GENERAL
    # ======================================================

    if not isinstance(
        scenario,
        dict
    ):
        return [
            "El escenario debe ser un diccionario."
        ]

    scenario_id = scenario.get(
        "id"
    )

    if not scenario_id:
        errors.append(
            "Falta el identificador del escenario."
        )

    if not scenario.get(
        "name"
    ):
        errors.append(
            f"{scenario_id}: falta el nombre."
        )

    if not scenario.get(
        "description"
    ):
        errors.append(
            f"{scenario_id}: falta la descripción."
        )

    roles = scenario.get(
        "roles"
    )

    if (
        not isinstance(
            roles,
            list
        )
        or not roles
    ):
        errors.append(
            f"{scenario_id}: debe definir roles."
        )

    metrics = scenario.get(
        "metrics"
    )

    if (
        not isinstance(
            metrics,
            list
        )
        or not metrics
    ):
        errors.append(
            f"{scenario_id}: debe definir métricas."
        )

    injects = scenario.get(
        "injects"
    )

    if (
        not isinstance(
            injects,
            list
        )
        or not injects
    ):
        errors.append(
            f"{scenario_id}: debe contener injects."
        )

        return errors

    # ======================================================
    # IDENTIFICADORES
    # ======================================================

    ids = []

    for item in injects:

        item_id = item.get(
            "id"
        )

        if not item_id:

            errors.append(
                (
                    f"{scenario_id}: existe un "
                    "elemento sin id."
                )
            )

            continue

        ids.append(
            item_id
        )

    duplicate_ids = {
        item_id
        for item_id in ids
        if ids.count(
            item_id
        ) > 1
    }

    for duplicate_id in sorted(
        duplicate_ids
    ):

        errors.append(
            (
                f"{scenario_id}: id duplicado "
                f"{duplicate_id}."
            )
        )

    items_by_id = {
        item.get("id"): item
        for item in injects
        if item.get("id")
    }

    # ======================================================
    # VALIDACIÓN DE CADA ELEMENTO
    # ======================================================

    for item in injects:

        item_id = item.get(
            "id",
            "SIN_ID"
        )

        item_type = item.get(
            "type"
        )

        if item_type not in {
            "ALERT",
            "EVIDENCE",
            "UPDATE",
            "GATE",
        }:

            errors.append(
                (
                    f"{scenario_id}: "
                    f"{item_id} tiene tipo "
                    f"no reconocido: {item_type}."
                )
            )

        # --------------------------------------------------
        # TIEMPO
        # --------------------------------------------------

        try:

            t_min = float(
                item.get(
                    "t_min",
                    0
                )
            )

            if t_min < 0:

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} tiene "
                        "t_min negativo."
                    )
                )

        except (
            TypeError,
            ValueError
        ):

            errors.append(
                (
                    f"{scenario_id}: "
                    f"{item_id} tiene "
                    "t_min inválido."
                )
            )

        # --------------------------------------------------
        # CONDITION
        # --------------------------------------------------

        condition = item.get(
            "condition"
        )

        if condition:

            required_gate = condition.get(
                "gate_id"
            )

            required_option = condition.get(
                "option"
            )

            required_options = condition.get(
                "options"
            )

            if (
                required_option is not None
                and required_options is not None
            ):

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} no puede definir "
                        "option y options simultáneamente."
                    )
                )

            if required_options is not None:

                if (
                    not isinstance(
                        required_options,
                        list
                    )
                    or not required_options
                ):

                    errors.append(
                        (
                            f"{scenario_id}: "
                            f"{item_id} debe definir "
                            "options como una lista "
                            "no vacía."
                        )
                    )

                    allowed_options = []

                else:

                    allowed_options = (
                        required_options
                    )

            elif required_option is not None:

                allowed_options = [
                    required_option
                ]

            else:

                allowed_options = []

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} debe definir "
                        "option u options."
                    )
                )

            referenced_item = (
                items_by_id.get(
                    required_gate
                )
            )

            if not referenced_item:

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} referencia "
                        f"{required_gate}, que no existe."
                    )
                )

            elif (
                referenced_item.get("type")
                != "GATE"
            ):

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} referencia "
                        f"{required_gate}, pero "
                        "no es un GATE."
                    )
                )

            else:

                valid_options = {
                    option.get("key")
                    for option
                    in referenced_item.get(
                        "options",
                        []
                    )
                }

                for required_value in (
                    allowed_options
                ):

                    if (
                        required_value
                        not in valid_options
                    ):

                        errors.append(
                            (
                                f"{scenario_id}: "
                                f"{item_id} requiere "
                                f"{required_gate}="
                                f"{required_value}, pero "
                                "esa opción no existe."
                            )
                        )

        # --------------------------------------------------
        # RELEASE AFTER
        # --------------------------------------------------

        release_after = item.get(
            "release_after"
        )

        if release_after:

            source_id = release_after.get(
                "inject_id"
            )

            if source_id not in items_by_id:

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} depende de "
                        f"{source_id}, que no existe."
                    )
                )

            try:

                delay_min = float(
                    release_after.get(
                        "delay_min",
                        0
                    )
                )

                if delay_min < 0:

                    errors.append(
                        (
                            f"{scenario_id}: "
                            f"{item_id} tiene "
                            "delay_min negativo."
                        )
                    )

            except (
                TypeError,
                ValueError
            ):

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} tiene "
                        "delay_min inválido."
                    )
                )

        # --------------------------------------------------
        # TELEMETRÍA
        # --------------------------------------------------

        telemetry_condition = item.get(
            "telemetry_condition"
        )

        if telemetry_condition:

            detector = telemetry_condition.get(
                "detector"
            )

            if (
                detector
                not in
                SUPPORTED_TELEMETRY_DETECTORS
            ):

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} utiliza "
                        f"detector no soportado: "
                        f"{detector}."
                    )
                )

            if not telemetry_condition.get(
                "expected_status"
            ):

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} no define "
                        "expected_status."
                    )
                )

        # --------------------------------------------------
        # GATES
        # --------------------------------------------------

        if item_type == "GATE":

            if not item.get(
                "question"
            ):

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} no tiene "
                        "pregunta."
                    )
                )

            role_required = item.get(
                "role_required"
            )

            if not role_required:

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} no define "
                        "role_required."
                    )
                )

            elif (
                isinstance(
                    roles,
                    list
                )
                and role_required
                not in roles
            ):

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} requiere "
                        f"rol {role_required}, "
                        "pero ese rol no está "
                        "declarado."
                    )
                )

            options = item.get(
                "options"
            )

            if (
                not isinstance(
                    options,
                    list
                )
                or not options
            ):

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} no tiene "
                        "opciones."
                    )
                )

                continue

            option_keys = []

            for option in options:

                option_key = option.get(
                    "key"
                )

                if not option_key:

                    errors.append(
                        (
                            f"{scenario_id}: "
                            f"{item_id} contiene "
                            "una opción sin key."
                        )
                    )

                else:

                    option_keys.append(
                        option_key
                    )

                if not option.get(
                    "label"
                ):

                    errors.append(
                        (
                            f"{scenario_id}: "
                            f"{item_id}/{option_key} "
                            "no tiene label."
                        )
                    )

                if (
                    "score"
                    not in option
                ):

                    errors.append(
                        (
                            f"{scenario_id}: "
                            f"{item_id}/{option_key} "
                            "no tiene score."
                        )
                    )

                if not option.get(
                    "outcome"
                ):

                    errors.append(
                        (
                            f"{scenario_id}: "
                            f"{item_id}/{option_key} "
                            "no tiene outcome."
                        )
                    )

            duplicate_options = {
                key
                for key in option_keys
                if option_keys.count(
                    key
                ) > 1
            }

            for key in sorted(
                duplicate_options
            ):

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{item_id} contiene "
                        f"opción duplicada {key}."
                    )
                )

    # ======================================================
    # CONFIGURACIÓN DE EVALUACIÓN
    # ======================================================

    evaluation = scenario.get(
        "evaluation",
        {}
    )

    gates = [
        item
        for item in injects
        if item.get("type")
        == "GATE"
    ]

    expected_response = evaluation.get(
        "expected_response_min",
        {}
    )

    weights = evaluation.get(
        "weights",
        {}
    )

    for gate in gates:

        gate_id = gate.get(
            "id"
        )

        if (
            gate_id
            not in expected_response
        ):

            errors.append(
                (
                    f"{scenario_id}: "
                    f"falta tiempo objetivo "
                    f"para {gate_id}."
                )
            )

        if gate_id not in weights:

            errors.append(
                (
                    f"{scenario_id}: "
                    f"falta peso para "
                    f"{gate_id}."
                )
            )

    performance_levels = evaluation.get(
        "performance_levels"
    )

    if (
        not isinstance(
            performance_levels,
            list
        )
        or not performance_levels
    ):

        errors.append(
            (
                f"{scenario_id}: no define "
                "niveles de desempeño."
            )
        )

    # ======================================================
    # CONFIGURACIÓN DE RUNTIME
    # ======================================================

    runtime = scenario.get(
        "runtime",
        {}
    )

    if not isinstance(
        runtime,
        dict
    ):

        errors.append(
            (
                f"{scenario_id}: runtime "
                "debe ser un diccionario."
            )
        )

    else:

        reset_actions = runtime.get(
            "reset_actions",
            []
        )

        if not isinstance(
            reset_actions,
            list
        ):

            errors.append(
                (
                    f"{scenario_id}: "
                    "runtime.reset_actions "
                    "debe ser una lista."
                )
            )

        else:

            if (
                len(reset_actions)
                != len(set(reset_actions))
            ):

                errors.append(
                    (
                        f"{scenario_id}: "
                        "runtime.reset_actions "
                        "contiene acciones duplicadas."
                    )
                )

            for action_name in reset_actions:

                if (
                    action_name
                    not in
                    SUPPORTED_RESET_ACTIONS
                ):

                    errors.append(
                        (
                            f"{scenario_id}: "
                            "acción de reinicio "
                            f"no soportada: "
                            f"{action_name}."
                        )
                    )

    # ======================================================
    # ACCIONES TÉCNICAS DE GATES
    # ======================================================

    technical_actions = scenario.get(
        "technical_actions",
        {}
    )

    if not isinstance(
        technical_actions,
        dict
    ):

        errors.append(
            (
                f"{scenario_id}: "
                "technical_actions "
                "debe ser un diccionario."
            )
        )

    else:

        for (
            gate_id,
            action_name
        ) in technical_actions.items():

            referenced_gate = (
                items_by_id.get(
                    gate_id
                )
            )

            if not referenced_gate:

                errors.append(
                    (
                        f"{scenario_id}: "
                        "technical_actions "
                        f"referencia {gate_id}, "
                        "que no existe."
                    )
                )

                continue

            if (
                referenced_gate.get("type")
                != "GATE"
            ):

                errors.append(
                    (
                        f"{scenario_id}: "
                        f"{gate_id} tiene acción "
                        "técnica configurada, "
                        "pero no es un GATE."
                    )
                )

            if (
                action_name
                not in
                SUPPORTED_GATE_ACTIONS
            ):

                errors.append(
                    (
                        f"{scenario_id}: "
                        "acción técnica "
                        f"no soportada: "
                        f"{action_name}."
                    )
                )

    return errors


def assert_scenario_valid(
    scenario: dict[str, Any]
) -> None:

    errors = validate_scenario(
        scenario
    )

    if errors:

        formatted_errors = "\n".join(
            f" - {error}"
            for error in errors
        )

        raise ValueError(
            (
                "Escenario inválido:\n"
                f"{formatted_errors}"
            )
        )
