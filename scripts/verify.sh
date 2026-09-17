#!/usr/bin/env bash

set -e

cd "$(dirname "$0")/.."

echo
echo "============================================================"
echo " CYBERRANGECORE - VALIDACIÓN COMPLETA"
echo "============================================================"
echo

echo "[1/7] Smoke test"
python tests/smoke_test.py

echo
echo "[2/7] Scenario contract test"
python tests/scenario_contract_test.py

echo
echo "[3/7] Session guard test"
python tests/session_guard_test.py

echo
echo "[4/7] Functional test"
python tests/functional_test.py

echo
echo "[5/7] CR-003 functional test"
python tests/cr003_functional_test.py

echo
echo "[6/7] End-to-end acceptance test"
python tests/e2e_test.py

echo
echo "[7/7] CR-003 end-to-end acceptance test"
python tests/cr003_e2e_test.py

echo
echo "============================================================"
echo " RESULTADO: CYBERRANGECORE VALIDACIÓN COMPLETA APROBADA"
echo "============================================================"
echo
