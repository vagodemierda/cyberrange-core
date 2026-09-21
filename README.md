# CyberRangeCore

CyberRangeCore es un entorno de entrenamiento en ciberseguridad desarrollado como herramienta propia para un proyecto de Maestría en Ciberseguridad.

La plataforma implementa escenarios de respuesta a incidentes basados en telemetría, roles CSIRT, toma de decisiones, consecuencias técnicas observables, métricas temporales y generación automática de After Action Reports.

El prototipo prioriza el ciclo:

    detección
        ↓
    análisis
        ↓
    decisión
        ↓
    consecuencia técnica
        ↓
    contención
        ↓
    recuperación
        ↓
    evaluación

## Estado actual

La versión actual contiene tres escenarios funcionales.

### CR-001 — Acceso no autorizado a aplicación institucional

Simula:

- intentos de autenticación fallidos;
- detección de actividad anómala;
- compromiso de autenticación;
- escalamiento;
- contención parcial o total;
- consecuencias técnicas HTTP 403/503;
- generación de reporte final.

### CR-002 — Modificación no autorizada de información académica

Simula:

- alteración de un registro académico;
- detección de pérdida de integridad;
- escalamiento;
- restauración del valor legítimo;
- aislamiento;
- bloqueo de nuevas modificaciones;
- generación de reporte final.

### CR-003 — Exfiltración y ransomware en plataforma institucional

Escenario avanzado con cinco decisiones interdependientes.

Incluye:

- compromiso de una cuenta institucional;
- clasificación inicial;
- respuesta sobre identidad comprometida;
- exfiltración de información;
- contención;
- ransomware simulado;
- aislamiento;
- recuperación.

CR-003 incorpora consecuencias acumulativas.

Una ruta deficiente puede producir:

    120 registros exfiltrados
            ↓
    CONTINUAR_MONITOREO
            ↓
    180 registros exfiltrados

y:

    38 recursos afectados
            ↓
    NO_INTERRUMPIR
            ↓
    78 recursos afectados

Una respuesta adecuada puede finalizar con:

    stage = RECOVERED
    service_available = true
    service_rebuilt = true
    residual_risk = false

Una ruta adversa puede terminar con:

    stage = RECOVERING
    recovery_status = ISOLATED
    service_available = false

## Arquitectura

Tecnologías principales:

- Python 3.12
- FastAPI
- SQLAlchemy
- SQLite
- Jinja2
- PyYAML
- HTML/CSS
- telemetría JSONL

Arquitectura conceptual:

    CyberRangeCore
    │
    ├── Core
    │   ├── motor de escenarios
    │   ├── sesiones
    │   ├── decisiones
    │   ├── scoring
    │   ├── Detector Registry
    │   ├── Action Registry
    │   └── After Action Report
    │
    └── Target Application
        ├── autenticación controladamente vulnerable
        ├── registros académicos
        ├── generación de telemetría
        └── incidente avanzado simulado

El Core utiliza el puerto 8000.

El Target utiliza el puerto 9000.

## Escenarios configurables

Los escenarios se encuentran en:

    scenarios/CR-001.yaml
    scenarios/CR-002.yaml
    scenarios/CR-003.yaml

Un escenario puede declarar:

- roles;
- métricas;
- injects;
- gates;
- condiciones;
- dependencias;
- condiciones de telemetría;
- acciones técnicas;
- acciones de reinicio;
- parámetros de evaluación.

CyberRangeCore valida el contrato del escenario antes de su utilización.

## Extensibilidad

Las capacidades de detección utilizan un Detector Registry.

Detectores actuales:

    AUTHENTICATION
    COMPROMISE
    DATA_INTEGRITY
    ACCOUNT_COMPROMISE
    EXFILTRATION
    RANSOMWARE

Las consecuencias técnicas utilizan un Action Registry.

Entre las acciones disponibles se encuentran:

    CONTAINMENT_RESPONSE
    INTEGRITY_RESPONSE
    ADVANCED_IDENTITY_RESPONSE
    ADVANCED_EXFILTRATION_RESPONSE
    ADVANCED_RANSOMWARE_RESPONSE
    ADVANCED_RECOVERY_RESPONSE

CR-003 fue incorporado sin introducir lógica específica del escenario dentro de core/main.py.

## Persistencia

El Core utiliza:

    data/cyberrange.db

La aplicación objetivo utiliza:

    target_app/data/portal.db

La telemetría se almacena en:

    target_app/logs/events.jsonl

Los estados controlados del laboratorio incluyen:

    data/containment_state.json
    data/integrity_state.json
    data/advanced_incident_state.json

## Instalación

### 1. Clonar

    git clone https://github.com/vagodemierda/cyberrange-core.git
    cd cyberrange-core

### 2. Crear entorno virtual

    python3.12 -m venv .venv
    source .venv/bin/activate

### 3. Instalar dependencias

    python -m pip install --upgrade pip
    pip install -r requirements.txt

### 4. Inicializar Core

    python -m core.init_db

Salida esperada:

    DB inicializada.

### 5. Inicializar Target

    python -m target_app.init_db

## Ejecución

Se recomienda utilizar tres terminales.

### Terminal 1 — Core

    cd ~/cyberrange-core
    source .venv/bin/activate
    uvicorn core.main:app --reload --host 0.0.0.0 --port 8000

Interfaz:

    http://127.0.0.1:8000

### Terminal 2 — Target

    cd ~/cyberrange-core
    source .venv/bin/activate
    uvicorn target_app.app:app --reload --host 0.0.0.0 --port 9000

Target:

    http://127.0.0.1:9000

### Terminal 3 — Operaciones

    cd ~/cyberrange-core
    source .venv/bin/activate

## Credenciales demostrativas

Usuario:

    estudiante
    Demo-2026

Administrador:

    admin_lab
    Admin-CR-2026

Estas credenciales pertenecen únicamente al laboratorio.

## Roles

Los escenarios utilizan principalmente:

    SOC_ANALYST
    IR_LEAD

SOC_ANALYST participa en detección, clasificación, análisis y escalamiento.

IR_LEAD participa principalmente en contención, aislamiento y recuperación.

## Métricas

CyberRangeCore registra:

### TTD — Time To Detect

Tiempo asociado al reconocimiento o confirmación del incidente.

### TTE — Time To Escalate

Tiempo asociado al escalamiento.

### TTC — Time To Contain

Tiempo asociado a la adopción de una medida de contención.

Las métricas se calculan utilizando timestamps persistidos durante la sesión.

## Scoring

Cada Gate contiene opciones con puntuaciones configurables.

La evaluación puede incorporar:

- score de la decisión;
- peso del Gate;
- tiempo objetivo;
- penalización por demora;
- nivel final de desempeño.

Los pesos, tiempos objetivo, penalizaciones y niveles utilizados actualmente forman parte del modelo experimental del prototipo y no deben interpretarse como estándares universales de respuesta CSIRT.

## After Action Report

Cada sesión finalizada genera un reporte que incluye:

- puntuación;
- nivel;
- TTD;
- TTE;
- TTC;
- decisiones;
- justificaciones;
- consecuencias;
- penalizaciones;
- información técnica;
- recomendaciones.

## Validación automática

La validación completa se ejecuta con:

    ./scripts/verify.sh

La versión actual contiene ocho capas:

1. Smoke Test.
2. Scenario Contract Test.
3. Session Guard Test.
4. Functional Test CR-001/CR-002.
5. CR-003 Functional Test.
6. E2E Acceptance Test CR-001/CR-002.
7. CR-003 E2E Acceptance Test.
8. CR-003 Adverse Path Test.

Una ejecución correcta finaliza con:

    RESULTADO: CYBERRANGECORE VALIDACIÓN COMPLETA APROBADA

## Qué comprueban las pruebas

### Smoke Test

Comprueba:

- archivos esenciales;
- escenarios;
- identificadores;
- dependencias;
- gates;
- roles;
- métricas;
- rutas FastAPI;
- contrato estructural.

### Scenario Contract Test

Verifica el rechazo de configuraciones inválidas como:

- IDs duplicados;
- Gates inexistentes;
- opciones inexistentes;
- roles inválidos;
- detectores desconocidos;
- acciones técnicas desconocidas;
- dependencias inválidas.

### Session Guard Test

Comprueba:

- sesión inexistente;
- Gate inexistente;
- Gate anticipado;
- opción inválida;
- justificación vacía;
- decisión duplicada;
- rama incorrecta;
- decisiones después de finalizar;
- segunda finalización.

### Functional Tests

Comprueban directamente detectores, Target y consecuencias técnicas.

### E2E Tests

Ejecutan el recorrido completo:

    sesión
      ↓
    telemetría
      ↓
    detector
      ↓
    decisión
      ↓
    consecuencia
      ↓
    persistencia
      ↓
    finalización
      ↓
    reporte

Las pruebas restauran automáticamente el estado previo del laboratorio.

## Ruta adecuada de CR-003

Ejemplo:

    INVESTIGAR
        ↓
    ESCALAR
        ↓
    BLOQUEAR_CUENTA
        ↓
    AISLAR_HOST
        ↓
    RECONSTRUIR_SERVICIO

Resultado:

    stage = RECOVERED
    service_available = true
    service_rebuilt = true
    residual_risk = false

## Ruta adversa de CR-003

Ejemplo:

    DESCARTAR
        ↓
    MANTENER_OBSERVACION
        ↓
    CONTINUAR_MONITOREO
        ↓
    NO_INTERRUMPIR
        ↓
    MANTENER_AISLAMIENTO

Resultado validado:

    exfiltrated_records = 180
    affected_records = 78
    stage = RECOVERING
    recovery_status = ISOLATED
    service_available = false

Esto permite representar consecuencias acumulativas derivadas de decisiones previas.

## Seguridad

CyberRangeCore contiene comportamientos inseguros deliberados exclusivamente con fines de entrenamiento.

CR-003 no implementa ransomware real.

El entorno:

- no cifra archivos reales;
- no realiza exfiltración externa;
- no ejecuta malware;
- no ataca infraestructura institucional;
- utiliza datos de laboratorio;
- utiliza estados simulados.

Se recomienda ejecutarlo en una máquina virtual o entorno controlado.

## Estructura principal

    cyberrange-core/
    │
    ├── core/
    │   ├── actions.py
    │   ├── db.py
    │   ├── init_db.py
    │   ├── main.py
    │   ├── models.py
    │   ├── scenario_loader.py
    │   ├── scenario_validator.py
    │   └── telemetry.py
    │
    ├── scenarios/
    │   ├── CR-001.yaml
    │   ├── CR-002.yaml
    │   └── CR-003.yaml
    │
    ├── target_app/
    │   ├── app.py
    │   └── init_db.py
    │
    ├── tests/
    │   ├── smoke_test.py
    │   ├── scenario_contract_test.py
    │   ├── session_guard_test.py
    │   ├── functional_test.py
    │   ├── e2e_test.py
    │   ├── cr003_functional_test.py
    │   ├── cr003_e2e_test.py
    │   └── cr003_adverse_path_test.py
    │
    ├── scripts/
    │   └── verify.sh
    │
    ├── advanced_incident_state.py
    ├── integrity_state.py
    ├── range_state.py
    ├── requirements.txt
    └── README.md

## Limitaciones

CyberRangeCore es actualmente un prototipo académico.

Entre sus limitaciones:

- persistencia SQLite;
- ejecución local;
- ausencia de autenticación de producción;
- ausencia de SIEM externo;
- tres escenarios implementados;
- efectos técnicos parcialmente simulados;
- ausencia de infraestructura distribuida;
- parámetros de evaluación pendientes de validación académica.

## Alcance académico

La implementación permite demostrar técnicamente que CyberRangeCore:

- ejecuta escenarios configurables;
- valida escenarios;
- procesa telemetría;
- utiliza detectores extensibles;
- soporta ramificación;
- registra decisiones y justificaciones;
- aplica consecuencias técnicas;
- registra métricas temporales;
- genera evidencia de desempeño;
- produce After Action Reports;
- soporta consecuencias acumulativas;
- permite incorporar escenarios sin introducir lógica específica dentro del núcleo.

La validación técnica del software no demuestra por sí misma que la herramienta desarrolle competencias profesionales en una población determinada.

La pertinencia pedagógica, usabilidad y posible desarrollo de competencias requieren la validación académica correspondiente.

## Verificación antes de demostración

Ejecutar:

    git status --short
    ./scripts/verify.sh

El repositorio debe permanecer limpio y la batería debe finalizar con:

    RESULTADO: CYBERRANGECORE VALIDACIÓN COMPLETA APROBADA

---

CyberRangeCore — Proyecto académico de Maestría en Ciberseguridad.
