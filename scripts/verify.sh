#!/usr/bin/env bash

set -e

cd "$(dirname "$0")/.."

echo
echo "============================================================"
echo " CYBERRANGECORE - VALIDACIÓN COMPLETA"
echo "============================================================"
echo

echo "[1/5] Smoke test"
python tests/smoke_test.py

echo
echo "[2/5] Scenario contract test"
python tests/scenario_contract_test.py

echo
echo "[3/5] Session guard test"
python tests/session_guard_test.py

echo
echo "[4/5] Functional test"
python tests/functional_test.py

echo
echo "[5/5] End-to-end acceptance test"
python tests/e2e_test.py

echo
echo "============================================================"
echo " RESULTADO: CYBERRANGECORE VALIDACIÓN COMPLETA APROBADA"
echo "============================================================"
echo
