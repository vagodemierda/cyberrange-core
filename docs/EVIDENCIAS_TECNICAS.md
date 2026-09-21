# Evidencias técnicas de CyberRangeCore

## 1. Propósito

Este documento organiza las principales evidencias técnicas de CyberRangeCore para su presentación, documentación académica y demostración.

CyberRangeCore es un entorno de entrenamiento desarrollado específicamente para el proyecto de Maestría en Ciberseguridad.

La herramienta integra:

- motor configurable de escenarios;
- telemetría;
- detectores;
- roles;
- decisiones;
- ramificación;
- consecuencias técnicas;
- métricas temporales;
- scoring;
- persistencia;
- After Action Report;
- pruebas automatizadas.

---

# 2. Evidencia de desarrollo propio

## E2.1 Motor del Cyber Range

Archivo principal:

    core/main.py

Funciones principales:

- creación de sesiones;
- ejecución de escenarios;
- liberación de injects;
- control de Gates;
- registro de decisiones;
- cálculo de desempeño;
- finalización de sesiones;
- generación de reportes.

Evidencia importante:

CR-003 fue incorporado sin introducir lógica específica del escenario dentro de core/main.py.

Comprobación:

    grep -n 'CR-003' core/main.py \
    || echo "OK: CR-003 integrado sin acoplarlo al núcleo"

Resultado esperado:

    OK: CR-003 integrado sin acoplarlo al núcleo

---

## E2.2 Escenarios configurables

Archivos:

    scenarios/CR-001.yaml
    scenarios/CR-002.yaml
    scenarios/CR-003.yaml

Los escenarios contienen:

- roles;
- métricas;
- injects;
- Gates;
- decisiones;
- condiciones;
- dependencias;
- condiciones de telemetría;
- acciones técnicas;
- parámetros de evaluación.

---

## E2.3 Contrato de escenarios

Archivo:

    core/scenario_validator.py

Permite detectar configuraciones incorrectas antes de su ejecución.

Entre los errores controlados:

- identificadores duplicados;
- Gate inexistente;
- rol inválido;
- opción inexistente;
- detector desconocido;
- dependencia inválida;
- acción de runtime desconocida;
- acción técnica desconocida.

Prueba asociada:

    tests/scenario_contract_test.py

---

# 3. Evidencia de telemetría y detección

## E3.1 Telemetría

Archivo:

    target_app/logs/events.jsonl

Eventos implementados incluyen:

    LOGIN_FAILURE
    AUTH_BYPASS
    DATA_TAMPERING
    ACCOUNT_COMPROMISE
    ANOMALOUS_LOGIN
    SENSITIVE_ACCESS
    BULK_RECORD_ACCESS
    EXPORT_CREATED
    DATA_EXFILTRATION
    MASS_FILE_WRITE
    FILE_RENAME_BURST
    RANSOM_NOTE_CREATED

---

## E3.2 Detector Registry

Archivo:

    core/telemetry.py

Detectores disponibles:

    AUTHENTICATION
    COMPROMISE
    DATA_INTEGRITY
    ACCOUNT_COMPROMISE
    EXFILTRATION
    RANSOMWARE

La arquitectura permite agregar detectores sin modificar el flujo principal del Core.

---

# 4. Evidencia de consecuencias técnicas

## E4.1 Action Registry

Archivo:

    core/actions.py

Acciones registradas incluyen:

    CONTAINMENT_RESPONSE
    INTEGRITY_RESPONSE
    ADVANCED_IDENTITY_RESPONSE
    ADVANCED_EXFILTRATION_RESPONSE
    ADVANCED_RANSOMWARE_RESPONSE
    ADVANCED_RECOVERY_RESPONSE

---

## E4.2 CR-001

Ejemplos de consecuencias:

- bloqueo de IP;
- contención parcial;
- aislamiento del servicio;
- HTTP 403;
- HTTP 503.

---

## E4.3 CR-002

Ejemplos:

- restauración de un registro académico;
- protección frente a nueva alteración;
- aislamiento del módulo;
- HTTP 403;
- HTTP 503.

---

## E4.4 CR-003

Ejemplos:

- bloqueo de cuenta comprometida;
- bloqueo de exfiltración;
- aislamiento de host;
- aislamiento de segmento;
- incremento acumulativo de daño;
- reconstrucción de servicio;
- recuperación del servicio.

---

# 5. Evidencia de consecuencias acumulativas

CR-003 permite demostrar que una decisión modifica el estado posterior del incidente.

## Ruta adversa

Secuencia:

    DESCARTAR
        ↓
    MANTENER_OBSERVACION
        ↓
    CONTINUAR_MONITOREO
        ↓
    NO_INTERRUMPIR
        ↓
    MANTENER_AISLAMIENTO

Consecuencia observada:

    exfiltrated_records:
    120 → 180

    affected_records:
    38 → 78

Estado final:

    stage = RECOVERING
    recovery_status = ISOLATED
    service_available = false

Prueba:

    tests/cr003_adverse_path_test.py

---

# 6. Evidencia de respuesta adecuada

Ruta validada:

    INVESTIGAR
        ↓
    ESCALAR
        ↓
    BLOQUEAR_CUENTA
        ↓
    AISLAR_HOST
        ↓
    RECONSTRUIR_SERVICIO

Estado final:

    stage = RECOVERED
    service_available = true
    service_rebuilt = true
    residual_risk = false

Prueba:

    tests/cr003_e2e_test.py

---

# 7. Evidencia de métricas

CyberRangeCore registra:

- TTD — Time To Detect;
- TTE — Time To Escalate;
- TTC — Time To Contain.

Las métricas se calculan utilizando timestamps persistidos durante la sesión.

Los resultados aparecen en el After Action Report.

---

# 8. Evidencia de toma de decisiones

Cada decisión almacena:

- Gate;
- rol;
- opción seleccionada;
- score;
- timestamp;
- justificación.

También se controla:

- decisión duplicada;
- Gate fuera de rama;
- Gate anticipado;
- opción inválida;
- justificación vacía;
- decisiones después de finalizar.

Prueba:

    tests/session_guard_test.py

---

# 9. Evidencia de After Action Report

Archivo:

    core/templates/report.html

Incluye:

- puntuación;
- nivel de desempeño;
- TTD;
- TTE;
- TTC;
- decisiones;
- justificaciones;
- consecuencias;
- penalizaciones;
- recomendaciones.

---

# 10. Evidencia de validación automática

Comando:

    ./scripts/verify.sh

Capas actuales:

1. Smoke Test.
2. Scenario Contract Test.
3. Session Guard Test.
4. Functional Test CR-001/CR-002.
5. CR-003 Functional Test.
6. E2E Acceptance Test CR-001/CR-002.
7. CR-003 E2E Acceptance Test.
8. CR-003 Adverse Path Test.

Resultado esperado:

    RESULTADO: CYBERRANGECORE VALIDACIÓN COMPLETA APROBADA

---

# 11. Evidencia de reproducibilidad

Archivo:

    README.md

Contiene:

- instalación;
- dependencias;
- inicialización;
- ejecución;
- arquitectura;
- escenarios;
- pruebas;
- seguridad;
- limitaciones.

---

# 12. Evidencia de versionamiento

Repositorio Git.

Versiones estables relevantes:

    mvp-stable-2026-09-06
    release-candidate-2026-09-16
    release-candidate-cr003-2026-09-16

El historial permite demostrar la evolución incremental del desarrollo.

---

# 13. Alcance de estas evidencias

Estas evidencias permiten demostrar:

- funcionamiento técnico;
- desarrollo propio;
- configurabilidad;
- extensibilidad;
- persistencia;
- ejecución reproducible;
- consecuencias técnicas;
- medición automatizada;
- robustez del flujo.

No constituyen por sí mismas una validación del desarrollo de competencias profesionales en participantes.

La validación pedagógica y académica deberá definirse con el asesor dentro de la metodología del proyecto.
