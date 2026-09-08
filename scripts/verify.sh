#!/usr/bin/env bash

set -e

cd "$(dirname "$0")/.."

echo
echo "============================================================"
echo " CYBERRANGECORE - VALIDACIÓN COMPLETA"
echo "============================================================"
echo

echo "[1/4] Smoke test"
python tests/smoke_test.py

echo
echo "[2/4] Scenario contract test"
python tests/scenario_contract_test.py

echo
echo "[3/4] Functional test"
python tests/functional_test.py

echo
echo "[4/4] End-to-end acceptance test"
python tests/e2e_test.py

echo
echo "============================================================"
echo " RESULTADO: CYBERRANGECORE VALIDACIÓN COMPLETA APROBADA"
echo "============================================================"
echo
