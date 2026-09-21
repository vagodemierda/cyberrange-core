# Guion de demostración — CyberRangeCore

Duración objetivo: 10 minutos.

## 0:00–1:00 — Qué se construyó

Mensaje sugerido:

CyberRangeCore es un Cyber Range desarrollado específicamente para el proyecto. El objetivo no es solamente presentar vulnerabilidades, sino simular incidentes en los cuales los participantes reciben evidencia, toman decisiones según su rol y esas decisiones generan consecuencias técnicas medibles.

Mostrar:

- pantalla principal;
- catálogo con CR-001, CR-002 y CR-003.

No abrir código todavía.

---

## 1:00–2:00 — Arquitectura

Explicar brevemente:

    escenario YAML
          ↓
    motor CyberRangeCore
          ↓
    telemetría
          ↓
    Detector Registry
          ↓
    decisión
          ↓
    Action Registry
          ↓
    consecuencia técnica

Mensaje clave:

Los escenarios se encuentran separados del núcleo.

CR-003 pudo incorporarse sin escribir lógica específica del escenario dentro de core/main.py.

Si se desea demostrar:

    grep -n 'CR-003' core/main.py \
    || echo "OK: CR-003 integrado sin acoplarlo al núcleo"

---

## 2:00–3:00 — Escenarios

Mostrar rápidamente:

### CR-001

Acceso no autorizado.

Conceptos:

- detección;
- escalamiento;
- compromiso;
- contención.

### CR-002

Modificación no autorizada de información.

Conceptos:

- integridad;
- restauración;
- aislamiento.

### CR-003

Exfiltración y ransomware.

Conceptos:

- cinco decisiones;
- incidente progresivo;
- consecuencias acumulativas;
- recuperación.

Dedicar la mayor parte de la demostración a CR-003.

---

## 3:00–6:30 — Demostración CR-003

Crear sesión.

Generar compromiso:

    curl -i -X POST \
      http://127.0.0.1:9000/advanced/compromise

Mostrar que aparece evidencia en la consola.

Tomar:

    INVESTIGAR

Después:

    ESCALAR

Generar exfiltración:

    curl -i -X POST \
      http://127.0.0.1:9000/advanced/exfiltrate

Mostrar:

    exfiltrated_records = 120

Tomar:

    BLOQUEAR_CUENTA

Repetir:

    curl -i -X POST \
      http://127.0.0.1:9000/advanced/exfiltrate

Resultado esperado:

    HTTP 403

Mensaje clave:

La decisión no solamente modifica el puntaje. Modifica técnicamente el estado del entorno.

---

## 6:30–7:30 — Ransomware y recuperación

Generar ransomware:

    curl -i -X POST \
      http://127.0.0.1:9000/advanced/ransomware

Mostrar:

    affected_records = 38

Tomar:

    AISLAR_HOST

Volver a ejecutar ransomware.

Resultado esperado:

    HTTP 403

Finalmente:

    RECONSTRUIR_SERVICIO

Comprobar:

    curl -s \
      http://127.0.0.1:9000/advanced/status \
      | python -m json.tool

Mostrar:

    stage = RECOVERED
    service_rebuilt = true
    service_available = true
    residual_risk = false

---

## 7:30–8:30 — Consecuencias acumulativas

No ejecutar necesariamente en vivo.

Explicar que existe una prueba automatizada de ruta adversa.

Mostrar:

    tests/cr003_adverse_path_test.py

Resultado validado:

    exfiltrated_records:
    120 → 180

    affected_records:
    38 → 78

Resultado final:

    stage = RECOVERING
    recovery_status = ISOLATED
    service_available = false

Mensaje clave:

Las decisiones tempranas modifican el estado futuro del incidente.

---

## 8:30–9:15 — After Action Report

Finalizar la sesión.

Mostrar reporte.

Señalar:

- score;
- nivel;
- TTD;
- TTE;
- TTC;
- decisiones;
- justificaciones;
- consecuencias;
- recomendaciones.

Mensaje clave:

CyberRangeCore conserva evidencia objetiva del desempeño del participante.

---

## 9:15–10:00 — Validación técnica

En terminal:

    ./scripts/verify.sh

No es necesario esperar toda la ejecución durante la reunión si el tiempo es limitado.

Explicar las ocho capas:

1. Smoke.
2. Contrato de escenarios.
3. Guardas de sesión.
4. Funcional CR-001/CR-002.
5. Funcional CR-003.
6. E2E CR-001/CR-002.
7. E2E CR-003.
8. Ruta adversa CR-003.

Resultado:

    RESULTADO: CYBERRANGECORE VALIDACIÓN COMPLETA APROBADA

Cerrar con:

La implementación funcional está terminada. El siguiente paso que quisiera definir con usted es la estrategia de validación académica y la adaptación final de la metodología y documentación del trabajo de grado.

---

# Preguntas probables

## ¿Esto utiliza DVWA, Juice Shop o un Cyber Range preconstruido?

No.

CyberRangeCore implementa su propio motor de escenarios, aplicación objetivo, telemetría, mecanismos de decisión, scoring, consecuencias y reportes.

Se utilizan tecnologías de propósito general como Python, FastAPI, SQLite y YAML.

---

## ¿Qué aporta frente a un laboratorio vulnerable?

El objetivo no es únicamente explotar una vulnerabilidad.

La plataforma incorpora:

- roles;
- evidencia progresiva;
- decisiones;
- ramificación;
- tiempo;
- consecuencias;
- evaluación;
- After Action Report.

---

## ¿Cómo se demuestra que las decisiones importan?

CR-003 dispone de rutas técnicamente diferentes.

Ruta adecuada:

    RECOVERED
    service_available = true
    residual_risk = false

Ruta adversa:

    180 registros exfiltrados
    78 recursos afectados
    RECOVERING
    service_available = false

---

## ¿Los escenarios están codificados directamente?

No.

Los escenarios se configuran mediante YAML.

Las capacidades se conectan mediante Detector Registry y Action Registry.

---

## ¿Es ransomware real?

No.

El escenario utiliza una simulación segura mediante estado, telemetría y consecuencias controladas.

No cifra archivos ni ejecuta malware.

---

## ¿TTD, TTE y TTC son estándares definitivos?

No se presentan como parámetros universales.

La plataforma los instrumenta técnicamente.

Los tiempos objetivo, pesos y umbrales actuales son parámetros experimentales que deben justificarse o validarse dentro de la metodología académica.

---

## ¿Ya se demostró que desarrolla competencias?

No todavía.

Se ha demostrado técnicamente que la herramienta puede instrumentar entrenamiento, capturar decisiones, medir tiempos y generar consecuencias.

La validación sobre pertinencia pedagógica o desarrollo de competencias debe definirse metodológicamente.

---

# Regla para la demostración

No empezar mostrando código.

Orden recomendado:

    problema
        ↓
    plataforma
        ↓
    escenario
        ↓
    decisión
        ↓
    consecuencia
        ↓
    resultado
        ↓
    evidencia técnica

El código se muestra solamente si el asesor pregunta por la implementación.
