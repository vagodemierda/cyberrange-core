#!/usr/bin/env bash

set -e

cd "$(dirname "$0")/.."

echo
echo "============================================================"
echo " CYBERRANGECORE - VALIDACIÓN COMPLETA"
echo "============================================================"
echo

echo "[1/8] Smoke test"
python tests/smoke_test.py

echo
echo "[2/8] Scenario contract test"
python tests/scenario_contract_test.py

echo
echo "[3/8] Session guard test"
python tests/session_guard_test.py

echo
echo "[4/8] Functional test"
python tests/functional_test.py

echo
echo "[5/8] CR-003 functional test"
python tests/cr003_functional_test.py

echo
echo "[6/8] End-to-end acceptance test"
python tests/e2e_test.py

echo
echo "[7/8] CR-003 end-to-end acceptance test"
python tests/cr003_e2e_test.py

echo
echo "[8/8] CR-003 adverse path test"
python tests/cr003_adverse_path_test.py

echo
echo "============================================================"
echo " RESULTADO: CYBERRANGECORE VALIDACIÓN COMPLETA APROBADA"
echo "============================================================"
echo
